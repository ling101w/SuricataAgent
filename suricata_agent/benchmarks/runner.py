"""运行小型检测 benchmark，并汇总生成、验证和复杂度指标。"""

from __future__ import annotations

import argparse
import json
import os
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from production import PIPELINE_ID, WorkflowConfig, run_generation
from suricata_agent.services.llm import create_chat_model
from suricata_agent.traffic.cases import derive_http_cases_with_diagnostics


PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = PROJECT_DIR / "benchmarks" / "matrix.json"


@dataclass(frozen=True, slots=True)
class BenchmarkCase:
    """一个可独立运行的典型漏洞流量案例。"""

    case_id: str
    category: str
    base: str
    poc: str
    http_request: bytes
    http_response: bytes


def _require_text(value: object, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{path} 必须是非空字符串")
    return value


def _headers(value: object, path: str) -> list[tuple[str, str]]:
    if value is None:
        return []
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} 必须是 JSON 对象")
    headers: list[tuple[str, str]] = []
    for name, header_value in value.items():
        if not isinstance(name, str) or not isinstance(header_value, str):
            raise ValueError(f"{path} 的字段名和值必须是字符串")
        if "\r" in name or "\n" in name or "\r" in header_value or "\n" in header_value:
            raise ValueError(f"{path} 不能包含换行符")
        headers.append((name, header_value))
    return headers


def _render_http_message(
    start_line: str,
    headers: list[tuple[str, str]],
    body: str,
) -> bytes:
    body_bytes = body.encode("utf-8")
    filtered = [
        (name, value)
        for name, value in headers
        if name.casefold() != "content-length"
    ]
    if body_bytes:
        filtered.append(("Content-Length", str(len(body_bytes))))
    if not any(name.casefold() == "connection" for name, _ in filtered):
        filtered.append(("Connection", "close"))
    lines = [start_line, *(f"{name}: {value}" for name, value in filtered)]
    return "\r\n".join(lines).encode("latin-1") + b"\r\n\r\n" + body_bytes


def _render_request(value: object, path: str) -> bytes:
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} 必须是 JSON 对象")
    method = _require_text(value.get("method"), f"{path}.method").upper()
    target = _require_text(value.get("target"), f"{path}.target")
    version = str(value.get("version", "HTTP/1.1"))
    headers = _headers(value.get("headers"), f"{path}.headers")
    if not any(name.casefold() == "host" for name, _ in headers):
        headers.insert(0, ("Host", "benchmark.invalid"))
    body = value.get("body", "")
    if not isinstance(body, str):
        raise ValueError(f"{path}.body 必须是字符串")
    return _render_http_message(f"{method} {target} {version}", headers, body)


def _render_response(value: object, path: str) -> bytes:
    if not isinstance(value, Mapping):
        raise ValueError(f"{path} 必须是 JSON 对象")
    status = value.get("status", 200)
    if not isinstance(status, int) or not 100 <= status <= 599:
        raise ValueError(f"{path}.status 必须是合法 HTTP 状态码")
    reason = str(value.get("reason", "OK"))
    version = str(value.get("version", "HTTP/1.1"))
    headers = _headers(value.get("headers"), f"{path}.headers")
    body = value.get("body", "")
    if not isinstance(body, str):
        raise ValueError(f"{path}.body 必须是字符串")
    return _render_http_message(f"{version} {status} {reason}", headers, body)


def load_benchmark_cases(path: str | Path = DEFAULT_MANIFEST) -> tuple[BenchmarkCase, ...]:
    """严格读取 benchmark manifest，并把结构化 HTTP 转成原始报文字节。"""
    manifest_path = Path(path).resolve()
    value = json.loads(manifest_path.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping) or value.get("version") != 1:
        raise ValueError("benchmark manifest version 必须为 1")
    raw_cases = value.get("cases")
    if not isinstance(raw_cases, list) or not raw_cases:
        raise ValueError("benchmark manifest 必须包含非空 cases 数组")

    cases: list[BenchmarkCase] = []
    seen_ids: set[str] = set()
    for index, raw in enumerate(raw_cases):
        path_prefix = f"$.cases[{index}]"
        if not isinstance(raw, Mapping):
            raise ValueError(f"{path_prefix} 必须是 JSON 对象")
        case_id = _require_text(raw.get("case_id"), f"{path_prefix}.case_id")
        if case_id in seen_ids:
            raise ValueError(f"benchmark case_id 重复：{case_id}")
        seen_ids.add(case_id)
        cases.append(
            BenchmarkCase(
                case_id=case_id,
                category=_require_text(raw.get("category"), f"{path_prefix}.category"),
                base=_require_text(raw.get("base"), f"{path_prefix}.base"),
                poc=_require_text(raw.get("poc"), f"{path_prefix}.poc"),
                http_request=_render_request(raw.get("request"), f"{path_prefix}.request"),
                http_response=_render_response(
                    raw.get("response"), f"{path_prefix}.response"
                ),
            )
        )
    return tuple(cases)


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _selected_complexity(state: Mapping[str, Any]) -> Mapping[str, Any] | None:
    selected_index = state.get("selected_candidate")
    attempts = state.get("attempts")
    if not isinstance(selected_index, int) or not isinstance(attempts, Sequence):
        return None
    for attempt in reversed(attempts):
        if not isinstance(attempt, Mapping):
            continue
        candidates = attempt.get("candidates")
        if not isinstance(candidates, Sequence):
            continue
        for candidate in candidates:
            if (
                isinstance(candidate, Mapping)
                and candidate.get("candidate_index") == selected_index
                and isinstance(candidate.get("complexity"), Mapping)
            ):
                return candidate["complexity"]
    return None


def aggregate_benchmark_results(
    runs: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    """把多案例工作流状态聚合成稳定、机器可比较的回归指标。"""
    positive_total = 0
    positive_passed = 0
    negative_total = 0
    negative_false_positives = 0
    negative_unevaluated = 0
    candidates_evaluated = 0
    candidates_passed = 0
    primary_candidates_evaluated = 0
    primary_candidates_passed = 0
    supplemental_candidates_evaluated = 0
    supplemental_candidates_passed = 0
    retries = 0
    selected_complexities: list[Mapping[str, Any]] = []
    case_summaries: list[dict[str, Any]] = []

    for run in runs:
        state_value = run.get("state", {})
        state = state_value if isinstance(state_value, Mapping) else {}
        validation_value = state.get("validation_result", {})
        validation = validation_value if isinstance(validation_value, Mapping) else {}
        sample_results = validation.get("sample_results", ())
        case_positive = 0
        case_positive_passed = 0
        case_negative = 0
        case_false_positives = 0
        if isinstance(sample_results, Sequence):
            for sample in sample_results:
                if not isinstance(sample, Mapping):
                    continue
                if sample.get("applicable") is False:
                    continue
                if sample.get("expected") == "no_alert":
                    case_negative += 1
                    if not bool(sample.get("passed")):
                        case_false_positives += 1
                else:
                    case_positive += 1
                    if bool(sample.get("passed")):
                        case_positive_passed += 1
        if not case_positive and not case_negative:
            matrix_value = state.get("sample_matrix", ())
            if isinstance(matrix_value, Sequence):
                case_positive = sum(
                    isinstance(sample, Mapping)
                    and sample.get("expected") == "alert"
                    for sample in matrix_value
                )
                negative_unevaluated += sum(
                    isinstance(sample, Mapping)
                    and sample.get("expected") == "no_alert"
                    for sample in matrix_value
                )
            if not case_positive and not matrix_value:
                expected_value = run.get("expected_samples", {})
                if isinstance(expected_value, Mapping):
                    case_positive = max(
                        0,
                        int(expected_value.get("positive", 0) or 0),
                    )
                    negative_unevaluated += max(
                        0,
                        int(expected_value.get("negative", 0) or 0),
                    )

        attempts_value = state.get("attempts", ())
        attempts = attempts_value if isinstance(attempts_value, Sequence) else ()
        case_candidates_evaluated = 0
        case_candidates_passed = 0
        case_primary_evaluated = 0
        case_primary_passed = 0
        case_supplemental_evaluated = 0
        case_supplemental_passed = 0
        for attempt in attempts:
            if not isinstance(attempt, Mapping):
                continue
            candidate_values = attempt.get("candidates", ())
            if not isinstance(candidate_values, Sequence):
                continue
            for candidate in candidate_values:
                if not isinstance(candidate, Mapping):
                    continue
                case_candidates_evaluated += 1
                passed = bool(candidate.get("passed"))
                if passed:
                    case_candidates_passed += 1
                if candidate.get("detection_scope", "case_specific") == "case_specific":
                    case_primary_evaluated += 1
                    if passed:
                        case_primary_passed += 1
                else:
                    case_supplemental_evaluated += 1
                    if passed:
                        case_supplemental_passed += 1

        attempt_count = state.get("attempt", len(attempts))
        case_retries = max(0, int(attempt_count or 0) - 1)
        complexity = _selected_complexity(state)
        if complexity is not None:
            selected_complexities.append(complexity)

        positive_total += case_positive
        positive_passed += case_positive_passed
        negative_total += case_negative
        negative_false_positives += case_false_positives
        candidates_evaluated += case_candidates_evaluated
        candidates_passed += case_candidates_passed
        primary_candidates_evaluated += case_primary_evaluated
        primary_candidates_passed += case_primary_passed
        supplemental_candidates_evaluated += case_supplemental_evaluated
        supplemental_candidates_passed += case_supplemental_passed
        retries += case_retries
        case_summaries.append(
            {
                "case_id": run.get("case_id"),
                "category": run.get("category"),
                "status": state.get("status", "failed"),
                "positive_recall": _ratio(case_positive_passed, case_positive),
                "negative_fp_rate": _ratio(case_false_positives, case_negative),
                "candidate_pass_rate": _ratio(
                    case_candidates_passed, case_candidates_evaluated
                ),
                "primary_candidate_pass_rate": _ratio(
                    case_primary_passed, case_primary_evaluated
                ),
                "supplemental_candidate_pass_rate": _ratio(
                    case_supplemental_passed, case_supplemental_evaluated
                ),
                "retry_count": case_retries,
                "rule_complexity": dict(complexity) if complexity is not None else None,
                "failure_code": state.get("failure_code"),
            }
        )

    complexity_fields = (
        "estimated_cost",
        "pcre_count",
        "content_count",
        "sticky_buffer_count",
        "content_bytes",
    )
    average_complexity = {
        field: round(
            sum(float(item.get(field, 0)) for item in selected_complexities)
            / len(selected_complexities),
            3,
        )
        for field in complexity_fields
    } if selected_complexities else None
    passed_cases = sum(item["status"] == "passed" for item in case_summaries)
    return {
        "pipeline_id": PIPELINE_ID,
        "case_count": len(case_summaries),
        "passed_case_count": passed_cases,
        "case_pass_rate": _ratio(passed_cases, len(case_summaries)),
        "positive_recall": _ratio(positive_passed, positive_total),
        "positive_samples": positive_total,
        "negative_fp_rate": _ratio(negative_false_positives, negative_total),
        "negative_false_positives": negative_false_positives,
        "negative_samples": negative_total,
        "negative_samples_unevaluated": negative_unevaluated,
        "candidate_pass_rate": _ratio(candidates_passed, candidates_evaluated),
        "candidates_passed": candidates_passed,
        "candidates_evaluated": candidates_evaluated,
        "primary_candidate_pass_rate": _ratio(
            primary_candidates_passed,
            primary_candidates_evaluated,
        ),
        "primary_candidates_passed": primary_candidates_passed,
        "primary_candidates_evaluated": primary_candidates_evaluated,
        "supplemental_candidate_pass_rate": _ratio(
            supplemental_candidates_passed,
            supplemental_candidates_evaluated,
        ),
        "supplemental_candidates_passed": supplemental_candidates_passed,
        "supplemental_candidates_evaluated": supplemental_candidates_evaluated,
        "retry_count": retries,
        "average_retry_count": _ratio(retries, len(case_summaries)),
        "rule_complexity": average_complexity,
        "cases": case_summaries,
    }


def mutation_contract_report(cases: Sequence[BenchmarkCase]) -> dict[str, Any]:
    """不调用模型或 Suricata，只检查 benchmark 的派生样本规模和 skip。"""
    summaries: list[dict[str, Any]] = []
    for case in cases:
        derivation = derive_http_cases_with_diagnostics(
            case.http_request,
            case.http_response,
        )
        positive_count = sum(item[1] == "alert" for item in derivation.cases)
        negative_count = sum(item[1] == "no_alert" for item in derivation.cases)
        summaries.append(
            {
                "case_id": case.case_id,
                "category": case.category,
                "positive_samples": positive_count,
                "negative_samples": negative_count,
                "mutation_skips": [skip.public_dict() for skip in derivation.mutation_skips],
            }
        )
    return {
        "mode": "mutation-only",
        "case_count": len(summaries),
        "positive_samples": sum(item["positive_samples"] for item in summaries),
        "negative_samples": sum(item["negative_samples"] for item in summaries),
        "cases": summaries,
    }


def run_full_benchmark(
    cases: Sequence[BenchmarkCase],
    output_dir: str | Path,
    *,
    sid_start: int = 8_000_000,
    max_attempts: int = 3,
    suricata_bin: str | None = None,
    suricata_config: str | None = None,
    model: object | None = None,
    runner: Callable[..., Mapping[str, Any]] = run_generation,
) -> dict[str, Any]:
    """顺序运行完整链路；同一个模型实例用于整组案例。"""
    root = Path(output_dir).resolve()
    root.mkdir(parents=True, exist_ok=True)
    shared_model = model
    model_error: str | None = None
    if shared_model is None:
        try:
            shared_model = create_chat_model()
        except Exception as exc:
            model_error = str(exc)[:2_000] or exc.__class__.__name__
    runs: list[dict[str, Any]] = []
    for index, case in enumerate(cases):
        case_output = root / "cases" / case.case_id
        derivation = derive_http_cases_with_diagnostics(
            case.http_request,
            case.http_response,
        )
        expected_samples = {
            "positive": sum(item[1] == "alert" for item in derivation.cases),
            "negative": sum(item[1] == "no_alert" for item in derivation.cases),
        }
        if model_error is not None:
            state = {
                "status": "failed",
                "attempt": 0,
                "failure_code": "BENCHMARK_MODEL_ERROR",
                "failure_message": model_error,
                "attempts": [],
                "validation_result": None,
            }
        else:
            assert shared_model is not None
            try:
                state = runner(
                    case_id=case.case_id,
                    base=case.base,
                    poc=case.poc,
                    http_request=case.http_request,
                    http_response=case.http_response,
                    output_dir=case_output,
                    model=shared_model,
                    config=WorkflowConfig(
                        sid_start=sid_start + index * 10,
                        max_rule_attempts=max_attempts,
                        suricata_bin=suricata_bin,
                        suricata_config=suricata_config,
                    ),
                )
            except Exception as exc:
                state = {
                    "status": "failed",
                    "attempt": 0,
                    "failure_code": "BENCHMARK_RUN_ERROR",
                    "failure_message": str(exc)[:2_000],
                    "attempts": [],
                    "validation_result": None,
                }
        runs.append(
            {
                "case_id": case.case_id,
                "category": case.category,
                "expected_samples": expected_samples,
                "state": state,
            }
        )
        report = aggregate_benchmark_results(runs)
        (root / "benchmark-report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2, default=str) + "\n",
            encoding="utf-8",
        )
    return aggregate_benchmark_results(runs)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="运行 Suricata 规则生成 benchmark")
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path, default=Path("benchmark-artifacts"))
    parser.add_argument("--mode", choices=("mutation-only", "full"), default="mutation-only")
    parser.add_argument("--case", action="append", default=[], help="只运行指定 case_id")
    parser.add_argument("--sid-start", type=int, default=8_000_000)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--suricata-bin", default=os.getenv("SURICATA_BIN"))
    parser.add_argument("--suricata-config", default=os.getenv("SURICATA_CONFIG"))
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    cases = load_benchmark_cases(args.manifest)
    if args.case:
        requested = set(args.case)
        cases = tuple(case for case in cases if case.case_id in requested)
        missing = requested - {case.case_id for case in cases}
        if missing:
            raise ValueError("未知 benchmark case：" + "、".join(sorted(missing)))
    if args.mode == "mutation-only":
        report = mutation_contract_report(cases)
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "benchmark-report.json").write_text(
            json.dumps(report, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    else:
        report = run_full_benchmark(
            cases,
            args.output_dir,
            sid_start=args.sid_start,
            max_attempts=args.max_attempts,
            suricata_bin=args.suricata_bin,
            suricata_config=args.suricata_config,
        )
    print(json.dumps(report, ensure_ascii=False, indent=2, default=str))
    return 0 if args.mode == "mutation-only" or report["case_pass_rate"] == 1.0 else 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "BenchmarkCase",
    "aggregate_benchmark_results",
    "load_benchmark_cases",
    "mutation_contract_report",
    "run_full_benchmark",
]
