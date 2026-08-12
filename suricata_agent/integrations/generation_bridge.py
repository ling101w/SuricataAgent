"""Versioned JSON bridge for invoking the production generation pipeline."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

from production import PIPELINE_ID, WorkflowConfig, run_generation


CONTRACT_VERSION = 1
MAX_REQUEST_BYTES = 2 * 1024 * 1024


def _text(value: object) -> str:
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="backslashreplace")
    return str(value or "")


def _required_text(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name)
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{name} 必须是非空字符串")
    return value


def _optional_text(payload: Mapping[str, object], name: str) -> str:
    value = payload.get(name, "")
    if value is None:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{name} 必须是字符串")
    return value


def _integer(
    payload: Mapping[str, object],
    name: str,
    *,
    default: int | None = None,
    minimum: int,
    maximum: int,
) -> int:
    value = payload.get(name, default)
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{name} 必须是整数")
    if not minimum <= value <= maximum:
        raise ValueError(f"{name} 必须在 {minimum} 到 {maximum} 之间")
    return value


def load_bridge_request(path: str | Path) -> dict[str, object]:
    request_path = Path(path).resolve()
    if not request_path.is_file():
        raise FileNotFoundError(f"bridge 请求不存在：{request_path}")
    if request_path.stat().st_size > MAX_REQUEST_BYTES:
        raise ValueError("bridge 请求超过 2 MiB 限制")
    try:
        value = json.loads(request_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"bridge 请求不是有效 JSON：{exc}") from exc
    if not isinstance(value, dict):
        raise ValueError("bridge 请求根节点必须是对象")
    if value.get("contract_version") != CONTRACT_VERSION:
        raise ValueError(
            f"不支持的 bridge contract_version：{value.get('contract_version')!r}"
        )
    return value


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _existing_path(value: object) -> Path | None:
    if not isinstance(value, (str, Path)) or not str(value):
        return None
    path = Path(value).resolve()
    return path if path.is_file() else None


def _sample_counts(value: object) -> tuple[int, int]:
    if not isinstance(value, list):
        return 0, 0
    positive = 0
    negative = 0
    for item in value:
        if not isinstance(item, Mapping):
            continue
        if item.get("expected") == "alert":
            positive += 1
        elif item.get("expected") == "no_alert":
            negative += 1
    return positive, negative


def _atomic_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def _write_http_evidence(
    output_dir: Path,
    request: object,
    response: object,
) -> tuple[Path, Path]:
    request_path = output_dir / "bridge-http-request.raw"
    response_path = output_dir / "bridge-http-response.raw"
    request_path.write_text(_text(request), encoding="utf-8")
    response_path.write_text(_text(response), encoding="utf-8")
    return request_path, response_path


def run_bridge_request(
    payload: Mapping[str, object],
    output_dir: str | Path,
    *,
    runner: Callable[..., Mapping[str, Any]] = run_generation,
) -> dict[str, object]:
    """Run one generation request and return a path-oriented stable manifest."""
    if payload.get("contract_version") != CONTRACT_VERSION:
        raise ValueError("bridge contract_version 不匹配")

    case_id = _required_text(payload, "case_id")
    base = _required_text(payload, "base")
    poc = _optional_text(payload, "poc")
    http_request = _optional_text(payload, "http_request")
    http_response = _optional_text(payload, "http_response")
    python_poc = _optional_text(payload, "python_poc")
    input_mode = _optional_text(payload, "input_mode") or (
        "python_poc" if python_poc.strip() else "http"
    )
    python_poc_filename = _optional_text(payload, "python_poc_filename") or "poc.py"
    sid = _integer(payload, "sid", minimum=1, maximum=4_294_967_295)
    max_attempts = _integer(
        payload,
        "max_attempts",
        default=3,
        minimum=1,
        maximum=5,
    )
    if input_mode not in {"http", "python_poc"}:
        raise ValueError("input_mode 必须是 http 或 python_poc")
    if input_mode == "http" and (not http_request.strip() or python_poc.strip()):
        raise ValueError("http 模式必须仅提供 http_request")
    if input_mode == "python_poc" and (not python_poc.strip() or http_request.strip()):
        raise ValueError("python_poc 模式必须仅提供 python_poc")
    if not poc.strip() and not python_poc.strip():
        raise ValueError("poc 或 python_poc 至少提供一个")
    if not http_request.strip() and not python_poc.strip():
        raise ValueError("http_request 或 python_poc 至少提供一个")

    artifact_dir = Path(output_dir).resolve()
    artifact_dir.mkdir(parents=True, exist_ok=True)
    config = WorkflowConfig(
        sid_start=sid,
        max_rule_attempts=max_attempts,
        suricata_bin=_optional_text(payload, "suricata_bin") or None,
        suricata_config=_optional_text(payload, "suricata_config") or None,
        ruleops_path=str(artifact_dir / "rule-kb.json"),
    )
    state = dict(
        runner(
            base=base,
            poc=poc,
            http_request=http_request,
            http_response=http_response,
            output_dir=artifact_dir,
            case_id=case_id,
            python_poc=python_poc,
            python_poc_filename=python_poc_filename,
            config=config,
        )
    )

    validation = state.get("validation_result")
    sample_matrix = state.get("sample_matrix")
    positive_sample_count, negative_sample_count = _sample_counts(sample_matrix)
    engine_validation_passed = (
        isinstance(validation, Mapping) and validation.get("passed") is True
    )
    positive_match_result = (
        validation.get("positive_match_ok")
        if isinstance(validation, Mapping)
        else None
    )
    negative_match_result = (
        validation.get("negative_match_ok")
        if isinstance(validation, Mapping)
        else None
    )
    positive_match_ok = positive_match_result is True
    negative_match_ok = negative_match_result is True
    validation_passed = bool(
        engine_validation_passed
        and positive_sample_count > 0
        and negative_sample_count > 0
        and positive_match_ok
        and negative_match_ok
    )
    engine_passed = state.get("status") == "passed"
    passed = engine_passed and validation_passed
    failure_code = state.get("failure_code")
    failure_message = state.get("failure_message")
    if engine_passed and not validation_passed:
        if positive_sample_count == 0:
            failure_code = "BRIDGE_POSITIVE_SAMPLE_REQUIRED"
            failure_message = "完整矩阵验证至少需要一个正样本"
        elif negative_sample_count == 0:
            failure_code = "BRIDGE_NEGATIVE_SAMPLE_REQUIRED"
            failure_message = "完整矩阵验证至少需要一个负样本"
        elif not positive_match_ok:
            failure_code = "BRIDGE_POSITIVE_VALIDATION_REQUIRED"
            failure_message = "正样本验证未通过或未评估"
        elif not negative_match_ok:
            failure_code = "BRIDGE_NEGATIVE_VALIDATION_REQUIRED"
            failure_message = "负样本验证未通过或未评估"
        else:
            failure_code = "BRIDGE_VALIDATION_INCOMPLETE"
            failure_message = "生产流水线未返回完整矩阵验证结果"
    rule_text = _text(state.get("rules")).strip() if passed else ""
    rules_path = _existing_path(state.get("rules_path"))
    pcap_path = _existing_path(state.get("pcap_path"))
    report_path = _existing_path(state.get("report_path"))
    request_path, response_path = _write_http_evidence(
        artifact_dir,
        state.get("http_request", http_request),
        state.get("http_response", http_response),
    )

    artifact_paths = {
        "traffic_matrix": _existing_path(artifact_dir / "traffic-matrix.json"),
        "pcap_analysis": _existing_path(artifact_dir / "pcap-analysis.json"),
        "coverage_graph": _existing_path(artifact_dir / "coverage-graph.json"),
    }
    pcap_analysis = state.get("pcap_analysis")
    pcap_summary = (
        dict(pcap_analysis.get("summary", {}))
        if isinstance(pcap_analysis, Mapping)
        and isinstance(pcap_analysis.get("summary"), Mapping)
        else {}
    )

    manifest: dict[str, object] = {
        "contract_version": CONTRACT_VERSION,
        "pipeline_id": str(state.get("pipeline_id") or PIPELINE_ID),
        "case_id": case_id,
        "status": "passed" if passed else "failed",
        "engine_status": str(state.get("status") or "failed"),
        "failure_code": failure_code,
        "failure_message": failure_message,
        "artifact_dir": str(artifact_dir),
        "rule": {
            "text": rule_text,
            "path": str(rules_path) if passed and rules_path else "",
            "sha256": _sha256(rules_path) if passed and rules_path else "",
            "sid": sid,
        },
        "traffic": {
            "primary_pcap_path": str(pcap_path) if pcap_path else "",
            "primary_pcap_sha256": _sha256(pcap_path) if pcap_path else "",
            "sample_count": len(sample_matrix) if isinstance(sample_matrix, list) else 0,
            "tcp_summary": pcap_summary,
        },
        "evidence": {
            "http_request_path": str(request_path),
            "http_response_path": str(response_path),
        },
        "validation": {
            "passed": validation_passed,
            "engine_passed": engine_validation_passed,
            "report_path": str(report_path) if report_path else "",
            "positive_match_ok": positive_match_result,
            "negative_match_ok": negative_match_result,
            "positive_sample_count": positive_sample_count,
            "negative_sample_count": negative_sample_count,
            "positive_coverage": (
                validation.get("positive_coverage")
                if isinstance(validation, Mapping)
                else None
            ),
            "false_positive_count": (
                validation.get("false_positive_count")
                if isinstance(validation, Mapping)
                else None
            ),
        },
        "artifacts": {
            name: str(path) if path else "" for name, path in artifact_paths.items()
        },
    }
    if passed and (not rule_text or rules_path is None or pcap_path is None or report_path is None):
        manifest.update(
            {
                "status": "failed",
                "failure_code": "BRIDGE_ARTIFACT_INCOMPLETE",
                "failure_message": "生产流水线通过，但缺少规则、主 PCAP 或验证报告",
            }
        )
    return manifest


def _failure_manifest(case_id: str, exc: Exception) -> dict[str, object]:
    return {
        "contract_version": CONTRACT_VERSION,
        "pipeline_id": PIPELINE_ID,
        "case_id": case_id,
        "status": "failed",
        "engine_status": "bridge_error",
        "failure_code": "BRIDGE_ERROR",
        "failure_message": str(exc).strip() or exc.__class__.__name__,
    }


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="运行生产规则/流量生成 JSON bridge")
    parser.add_argument("--request", required=True, help="bridge 请求 JSON")
    parser.add_argument("--output-dir", required=True, help="生产工件输出目录")
    parser.add_argument("--result", required=True, help="bridge 结果清单 JSON")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    result_path = Path(args.result).resolve()
    case_id = "unknown"
    try:
        payload = load_bridge_request(args.request)
        case_id = str(payload.get("case_id") or case_id)
        manifest = run_bridge_request(payload, args.output_dir)
    except Exception as exc:
        manifest = _failure_manifest(case_id, exc)
    _atomic_json(result_path, manifest)
    print(json.dumps({
        "status": manifest["status"],
        "result": str(result_path),
    }, ensure_ascii=False))
    if manifest["status"] == "passed":
        return 0
    print(str(manifest.get("failure_message") or "bridge 执行失败"), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "CONTRACT_VERSION",
    "build_parser",
    "load_bridge_request",
    "main",
    "run_bridge_request",
]
