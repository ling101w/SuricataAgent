"""LLM 特征提取、确定性编译和 Suricata 样本矩阵验证工作流。"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import asdict, dataclass, field, is_dataclass
from pathlib import Path
from typing import Any, Literal, TypedDict

from langgraph.graph import END, START, StateGraph

from suricata_agent.domain.rules.compiler import (
    DetectionPlan,
    RuleLintError,
    compile_candidate,
    parse_detection_json,
)
from suricata_agent.domain.rules.diagnosis import diagnose_candidate
from suricata_agent.domain.rules.evidence import (
    evidence_fingerprint,
    evidence_fingerprint_id,
    novel_evidence,
)
from suricata_agent.domain.rules.ir import parse_suricata_rule, rule_ir_to_dict
from suricata_agent.domain.rules.knowledge import (
    CANDIDATE_ROLE_GUIDANCE,
    FALSE_POSITIVE_PENALTY,
    PCRE_PENALTY,
    POSITIVE_COVERAGE_WEIGHT,
)
from suricata_agent.domain.rules.strategy import (
    retrieve_strategy_clusters,
    validate_strategy_catalog,
)
from suricata_agent.legacy.final_judge import FinalJudgment, judge_passing_candidates
from suricata_agent.legacy.generate_rules import ChatModel, extract_detection_features
from suricata_agent.services.llm import create_chat_model
from suricata_agent.services.suricata import (
    RulePolicy,
    RuleValidationResult,
    SuricataRuntimeCheck,
    check_suricata_runtime,
    validate_rule_matrix,
)
from suricata_agent.traffic.cases import (
    TrafficSample,
    build_traffic_matrix,
    materialize_semantic_testcases,
)
from suricata_agent.traffic.pcap import PcapConfig


class AttemptRecord(TypedDict, total=False):
    attempt: int
    detection_json: str | None
    generation_error: dict[str, str] | None
    generation_ms: int
    compilation_ms: int
    validation_ms: int
    candidates: list[dict[str, Any]]
    selected_candidate: int | None
    selected_rule: str | None
    validation: RuleValidationResult | None
    diagnosis: dict[str, Any] | None
    final_judgment: dict[str, Any] | None
    selected_rule_ir: dict[str, Any] | None
    supplemental_rules: str
    supplemental_rule_irs: list[dict[str, Any]]
    strategy_context: list[dict[str, Any]]


class GenState(TypedDict, total=False):
    case_id: str
    base: str
    poc: str
    http_request: str | bytes
    http_response: str | bytes
    output_dir: str
    negative_pcap_paths: list[str]
    pcap_path: str
    traffic_samples: list[TrafficSample]
    sample_matrix: list[dict[str, object]]
    mutation_skips: list[dict[str, str]]
    detection_json: str | None
    detection_plan: DetectionPlan | None
    repair_feedback: dict[str, Any] | None
    candidate_results: list[dict[str, Any]]
    selected_candidate: int | None
    rules: str
    rules_path: str
    report_path: str
    attempt: int
    attempts: list[AttemptRecord]
    status: Literal["running", "passed", "failed"]
    runtime_check: SuricataRuntimeCheck
    validation_result: RuleValidationResult | None
    final_judgment: dict[str, Any] | None
    selected_rule_ir: dict[str, Any] | None
    supplemental_rules: str
    supplemental_rule_irs: list[dict[str, Any]]
    strategy_context: list[dict[str, Any]]
    failure_code: str | None
    failure_message: str | None


@dataclass(frozen=True, slots=True)
class WorkflowConfig:
    sid_start: int = 123
    max_rule_attempts: int = 3
    pcap_filename: str = "traffic.pcap"
    sample_dirname: str = "samples"
    suricata_bin: str | None = None
    suricata_config: str | None = None
    syntax_timeout: int = 30
    replay_timeout: int = 60
    strategy_catalog: str | None = None
    strategy_limit: int = 3
    pcap: PcapConfig = field(default_factory=PcapConfig)

    def __post_init__(self) -> None:
        if not 1 <= self.sid_start <= 4_294_967_295:
            raise ValueError("sid_start 必须是有效的 Suricata SID")
        if self.max_rule_attempts <= 0:
            raise ValueError("max_rule_attempts 必须大于 0")
        if not 1 <= self.strategy_limit <= 10:
            raise ValueError("strategy_limit 必须在 1 到 10 之间")
        for name, value in (
            ("pcap_filename", self.pcap_filename),
            ("sample_dirname", self.sample_dirname),
        ):
            if not value or Path(value).name != value:
                raise ValueError(f"{name} 必须是单独的名称，不能包含目录")


def _error_text(error: Exception) -> str:
    return str(error).strip()[:2_000] or error.__class__.__name__


def _load_strategy_catalog(path: str | None) -> Mapping[str, Any] | None:
    if not path:
        return None
    source = Path(path).resolve()
    if source.stat().st_size > 8 * 1024 * 1024:
        raise ValueError("Detection Strategy catalog 不能超过 8 MiB")
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, Mapping):
        raise ValueError("Detection Strategy catalog 顶层必须是对象")
    clusters = validate_strategy_catalog(value)
    return {"version": 1, "clusters": list(clusters)}


def _strategy_evidence_text(state: GenState) -> str:
    values: list[str] = [state.get("base", ""), state.get("poc", "")]
    for key in ("http_request", "http_response"):
        value = state.get(key, "")
        if isinstance(value, bytes):
            values.append(value.decode("utf-8", errors="backslashreplace"))
        else:
            values.append(str(value))
    return "\n".join(values)


def _json_ready(value: object) -> object:
    if is_dataclass(value) and not isinstance(value, type):
        return _json_ready(asdict(value))
    if isinstance(value, Path):
        return value.name
    if isinstance(value, Mapping):
        return {str(key): _json_ready(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_ready(item) for item in value]
    return value


def _atomic_write_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _write_json(path: Path, value: object) -> None:
    _atomic_write_text(
        path,
        json.dumps(_json_ready(value), ensure_ascii=False, indent=2) + "\n",
    )


def _upsert_attempt(
    attempts: Sequence[AttemptRecord],
    record: AttemptRecord,
) -> list[AttemptRecord]:
    updated = [dict(item) for item in attempts]
    if updated and updated[-1].get("attempt") == record.get("attempt"):
        updated[-1] = dict(record)
    else:
        updated.append(dict(record))
    return updated


def _persist_attempt(output_dir: str | Path, record: AttemptRecord) -> None:
    """增量保存单次尝试，进程中途失败时也能保留已有证据。"""
    number = int(record["attempt"])
    attempt_dir = Path(output_dir) / "attempts" / f"{number:03d}"
    attempt_dir.mkdir(parents=True, exist_ok=True)

    detection_json = record.get("detection_json")
    if detection_json:
        try:
            parsed = json.loads(detection_json)
        except json.JSONDecodeError:
            _atomic_write_text(attempt_dir / "model-response.txt", detection_json + "\n")
        else:
            if record.get("generation_error"):
                _atomic_write_text(
                    attempt_dir / "model-response.txt", detection_json + "\n"
                )
            else:
                _write_json(attempt_dir / "detection-plan.json", parsed)

    generation_error = record.get("generation_error")
    if generation_error:
        _write_json(attempt_dir / "generation-error.json", generation_error)

    for candidate in record.get("candidates", []):
        index = int(candidate.get("candidate_index", 0))
        if index <= 0:
            continue
        prefix = f"candidate-{index:02d}"
        rule = candidate.get("rule")
        if isinstance(rule, str) and rule:
            _atomic_write_text(attempt_dir / f"{prefix}.rules", rule + "\n")
        validation = candidate.get("validation")
        if isinstance(validation, Mapping):
            _write_json(attempt_dir / f"{prefix}-validation.json", validation)
        _write_json(attempt_dir / f"{prefix}-result.json", candidate)

    selected_rule = record.get("selected_rule")
    if selected_rule:
        _atomic_write_text(attempt_dir / "candidate.rules", selected_rule + "\n")
    if record.get("selected_rule_ir") is not None:
        _write_json(
            attempt_dir / "candidate.rule-ir.json",
            {"rules": [record["selected_rule_ir"]]},
        )
    supplemental_rules = record.get("supplemental_rules")
    if supplemental_rules:
        _atomic_write_text(
            attempt_dir / "supplemental.rules",
            supplemental_rules.rstrip() + "\n",
        )
    supplemental_rule_irs = record.get("supplemental_rule_irs", [])
    if supplemental_rule_irs:
        _write_json(
            attempt_dir / "supplemental.rule-ir.json",
            {"rules": supplemental_rule_irs},
        )
    if record.get("final_judgment") is not None:
        _write_json(attempt_dir / "final-judgment.json", record["final_judgment"])
    if record.get("validation") is not None:
        _write_json(attempt_dir / "validation.json", record["validation"])
    if record.get("diagnosis") is not None:
        _write_json(attempt_dir / "diagnosis.json", record["diagnosis"])
    _write_json(attempt_dir / "attempt.json", record)


def _candidate_validation(
    batch: RuleValidationResult,
    sid: int,
    *,
    direction: Literal["request", "response"] | None = None,
) -> RuleValidationResult:
    """从批量回放结果中按 SID 派生一个候选自己的评测矩阵。"""
    result: RuleValidationResult = dict(batch)  # type: ignore[assignment]
    result["expected_sids"] = [sid]
    result["errors"] = list(batch.get("errors", []))
    result["warnings"] = list(batch.get("warnings", []))
    result["quality_warnings"] = list(batch.get("quality_warnings", []))

    raw_samples = batch.get("sample_results", [])
    matrix_codes = {
        None,
        "NO_POSITIVE_MATCH",
        "NEGATIVE_FALSE_POSITIVE",
        "SAMPLE_MATRIX_MISMATCH",
    }
    if batch.get("error_code") not in matrix_codes:
        result["positive_matched_sids"] = (
            [sid] if sid in batch.get("positive_matched_sids", []) else []
        )
        result["negative_matched_sids"] = (
            [sid] if sid in batch.get("negative_matched_sids", []) else []
        )
        return result
    if not raw_samples:
        result["positive_matched_sids"] = (
            [sid] if sid in batch.get("positive_matched_sids", []) else []
        )
        result["negative_matched_sids"] = (
            [sid] if sid in batch.get("negative_matched_sids", []) else []
        )
        return result

    sample_results: list[dict[str, object]] = []
    positives: list[dict[str, object]] = []
    negatives: list[dict[str, object]] = []
    for raw in raw_samples:
        item = dict(raw)
        configured_sids = item.get("expected_any_sids", [])
        applicable_sids = {
            int(value)
            for value in configured_sids
            if isinstance(value, int) or str(value).isdigit()
        } if isinstance(configured_sids, Sequence) and not isinstance(
            configured_sids, (str, bytes)
        ) else set()
        if sid not in applicable_sids:
            item["expected_any_sids"] = []
            item["matched_sids"] = []
            item["passed"] = True
            item["applicable"] = False
            sample_results.append(item)
            continue
        matched = sid in item.get("matched_sids", [])
        expected = str(item.get("expected", "alert"))
        passed = matched if expected == "alert" else not matched
        item["expected_any_sids"] = [sid]
        item["matched_sids"] = [sid] if matched else []
        item["passed"] = passed
        item["applicable"] = True
        sample_results.append(item)
        (positives if expected == "alert" else negatives).append(item)

    false_negatives = [item for item in positives if not item["passed"]]
    false_positives = [item for item in negatives if not item["passed"]]
    positive_hits = len(positives) - len(false_negatives)
    result["sample_results"] = sample_results
    result["positive_coverage"] = positive_hits / len(positives) if positives else 0.0
    result["false_positive_count"] = len(false_positives)
    result["positive_match_ok"] = bool(positives) and not false_negatives
    result["negative_match_ok"] = not false_positives if negatives else None
    result["positive_matched_sids"] = [sid] if positive_hits else []
    result["negative_matched_sids"] = [sid] if false_positives else []
    result["validation_level"] = "sample_matrix"
    result["completed_stages"] = ["static", "syntax"]
    if positives and not false_negatives:
        result["completed_stages"].append("positive")
    if negatives and not false_positives:
        result["completed_stages"].append("negative")

    result["errors"] = []
    if false_negatives:
        result["errors"].append(
            "正向变体未告警：" + "、".join(str(item["name"]) for item in false_negatives)
        )
    if false_positives:
        result["errors"].append(
            "近似负样本产生告警："
            + "、".join(str(item["name"]) for item in false_positives)
        )

    if not positives:
        result["passed"] = False
        result["failed_stage"] = "positive"
        result["error_code"] = "POSITIVE_PCAP_REQUIRED"
        result["retryable"] = False
    elif false_negatives or false_positives:
        result["passed"] = False
        result["failed_stage"] = "samples"
        result["error_code"] = (
            "SAMPLE_MATRIX_MISMATCH"
            if false_negatives and false_positives
            else "NEGATIVE_FALSE_POSITIVE"
            if false_positives
            else "NO_POSITIVE_MATCH"
        )
        result["retryable"] = True
    else:
        result["passed"] = True
        result["failed_stage"] = None
        result["error_code"] = None
        result["retryable"] = False
    if direction == "response":
        response_samples = [
            item
            for item in sample_results
            if item.get("applicable") is True
            and item.get("validates") == "response_detection"
        ]
        response_positives = [
            item for item in response_samples if item.get("expected") == "alert"
        ]
        response_negatives = [
            item for item in response_samples if item.get("expected") == "no_alert"
        ]
        missing_oracles: list[str] = []
        if not response_positives:
            missing_oracles.append("正向响应变体")
            result["positive_match_ok"] = False
            result["completed_stages"] = [
                stage
                for stage in result["completed_stages"]
                if stage != "positive"
            ]
        if not response_negatives:
            missing_oracles.append("近似负响应变体")
            result["negative_match_ok"] = None
            result["completed_stages"] = [
                stage
                for stage in result["completed_stages"]
                if stage != "negative"
            ]
        if missing_oracles:
            result["passed"] = False
            result["failed_stage"] = "samples"
            result["error_code"] = "RESPONSE_ORACLE_REQUIRED"
            result["retryable"] = True
            result["errors"].append(
                "响应候选缺少"
                + "和".join(missing_oracles)
                + "，不能证明成功证据对表示变化和近似文本均可靠"
            )
    return result


def _remap_validation_sid(
    validation: RuleValidationResult,
    source_sid: int,
    target_sid: int,
) -> RuleValidationResult:
    result: RuleValidationResult = dict(validation)  # type: ignore[assignment]
    result["expected_sids"] = [target_sid]
    for key in ("positive_matched_sids", "negative_matched_sids"):
        result[key] = [target_sid] if source_sid in validation.get(key, []) else []
    remapped_samples: list[dict[str, object]] = []
    for value in validation.get("sample_results", []):
        item = dict(value)
        applicable = bool(item.get("applicable", True))
        item["expected_any_sids"] = [target_sid] if applicable else []
        item["matched_sids"] = (
            [target_sid]
            if applicable and source_sid in item.get("matched_sids", [])
            else []
        )
        remapped_samples.append(item)
    result["sample_results"] = remapped_samples
    return result


def _candidate_reference_metrics(
    validation: RuleValidationResult,
    complexity: Mapping[str, Any],
) -> dict[str, Any]:
    """提供可比较事实和旧启发式值；它们只作排序参考，不证明最佳。"""
    coverage = float(validation.get("positive_coverage", 0.0))
    false_positives = int(validation.get("false_positive_count", 0))
    pcre_count = int(complexity.get("pcre_count", 0))
    return {
        "positive_coverage": coverage,
        "false_positive_count": false_positives,
        "estimated_cost": int(complexity.get("estimated_cost", 0)),
        "pcre_count": pcre_count,
        "heuristic_rank_value": round(
            coverage * POSITIVE_COVERAGE_WEIGHT
            - false_positives * FALSE_POSITIVE_PENALTY
            - pcre_count * PCRE_PENALTY,
            3,
        ),
        "decision_authority": "reference_only",
    }


def _deterministic_primary_fallback(
    candidate_results: Sequence[dict[str, Any]],
) -> dict[str, Any] | None:
    """只用于没有多个通过候选时或 Final Judge 故障时的确定性兜底。"""
    primary = [
        item
        for item in candidate_results
        if item.get("detection_scope") == "case_specific"
        and isinstance(item.get("validation"), Mapping)
    ]
    passing = [item for item in primary if item.get("passed")]
    pool = passing or primary
    if not pool:
        return None
    return max(
        pool,
        key=lambda item: (
            float((item.get("reference_metrics") or {}).get("positive_coverage", 0.0)),
            -int((item.get("reference_metrics") or {}).get("false_positive_count", 0)),
            -int((item.get("complexity") or {}).get("estimated_cost", 0)),
            -int(item["candidate_index"]),
        ),
    )


def _sample_excerpt(sample: TrafficSample, limit: int = 6_000) -> str | None:
    if sample.request is None:
        return None
    text = sample.request.decode("utf-8", errors="backslashreplace")
    if len(text) <= limit:
        return text
    return text[:5_000] + "\n<request_truncated />\n" + text[-800:]


def _repair_feedback(
    diagnosis: Mapping[str, Any],
    validation: RuleValidationResult,
    samples: Sequence[TrafficSample],
    candidate_results: Sequence[Mapping[str, Any]],
) -> dict[str, Any]:
    by_name = {sample.name: sample for sample in samples}
    failed_samples: list[dict[str, Any]] = []
    for item in validation.get("sample_results", []):
        if item.get("passed"):
            continue
        summary = dict(item)
        sample = by_name.get(str(item.get("name", "")))
        if sample is not None:
            summary["request_excerpt"] = _sample_excerpt(sample)
        failed_samples.append(summary)
    return {
        "diagnosis": dict(diagnosis),
        "failed_samples": failed_samples,
        "candidate_metrics": [
            {
                "candidate_index": item.get("candidate_index"),
                "role": item.get("role"),
                "detection_scope": item.get("detection_scope"),
                "selection_tier": item.get("selection_tier"),
                "reference_metrics": item.get("reference_metrics"),
                "passed": item.get("passed"),
                "compile_error": item.get("compile_error"),
            }
            for item in candidate_results
        ],
    }


def build_workflow(
    model: ChatModel | None = None,
    *,
    config: WorkflowConfig | None = None,
    model_factory: Callable[[], ChatModel] = create_chat_model,
    runtime_checker: Callable[..., SuricataRuntimeCheck] = check_suricata_runtime,
    traffic_builder: Callable[..., list[TrafficSample]] = build_traffic_matrix,
    feature_extractor: Callable[..., str] = extract_detection_features,
    matrix_validator: Callable[..., RuleValidationResult] = validate_rule_matrix,
    failure_diagnoser: Callable[..., dict[str, Any]] = diagnose_candidate,
    semantic_materializer: Callable[..., list[TrafficSample]] = materialize_semantic_testcases,
    candidate_judge: Callable[..., FinalJudgment] = judge_passing_candidates,
):
    """编译固定工作流；模型负责策略与最终语义判断，代码负责所有证明门禁。"""
    workflow_config = config or WorkflowConfig()
    chat_model = model
    strategy_catalog: Mapping[str, Any] | None = None
    strategy_catalog_error: str | None = None
    try:
        strategy_catalog = _load_strategy_catalog(workflow_config.strategy_catalog)
    except Exception as exc:
        strategy_catalog_error = _error_text(exc)

    def preflight_node(_: GenState) -> dict[str, Any]:
        if strategy_catalog_error is not None:
            return {
                "status": "failed",
                "failure_code": "STRATEGY_CATALOG_ERROR",
                "failure_message": strategy_catalog_error,
            }
        try:
            runtime = runtime_checker(
                suricata_bin=workflow_config.suricata_bin,
                config_path=workflow_config.suricata_config,
            )
        except Exception as exc:
            return {
                "status": "failed",
                "failure_code": "SURICATA_PREFLIGHT_ERROR",
                "failure_message": _error_text(exc),
            }
        if not runtime["ok"]:
            return {
                "runtime_check": runtime,
                "status": "failed",
                "failure_code": runtime["error_code"],
                "failure_message": runtime["message"],
            }
        return {
            "runtime_check": runtime,
            "status": "running",
            "failure_code": None,
            "failure_message": None,
        }

    def build_samples_node(state: GenState) -> dict[str, Any]:
        missing = [
            value
            for value in state.get("negative_pcap_paths", [])
            if not Path(value).is_file()
        ]
        if missing:
            return {
                "status": "failed",
                "failure_code": "NEGATIVE_PCAP_NOT_FOUND",
                "failure_message": f"负样本 PCAP 不存在：{Path(missing[0]).name}",
            }
        try:
            samples = traffic_builder(
                Path(state["output_dir"]) / workflow_config.sample_dirname,
                state["http_request"],
                state["http_response"],
                config=workflow_config.pcap,
                uploaded_negative_pcaps=tuple(state.get("negative_pcap_paths", [])),
            )
            original = next(
                sample
                for sample in samples
                if sample.name == "positive-original" and sample.expected == "alert"
            )
            compatibility_pcap = Path(state["output_dir"]) / workflow_config.pcap_filename
            compatibility_pcap.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original.pcap_path, compatibility_pcap)
        except Exception as exc:
            return {
                "status": "failed",
                "failure_code": "PCAP_BUILD_ERROR",
                "failure_message": _error_text(exc),
            }
        return {
            "traffic_samples": samples,
            "sample_matrix": [sample.public_dict() for sample in samples],
            "mutation_skips": [
                skip.public_dict()
                for skip in getattr(samples, "mutation_skips", ())
            ],
            "pcap_path": str(compatibility_pcap),
            "status": "running",
        }

    def extract_features_node(state: GenState) -> dict[str, Any]:
        nonlocal chat_model
        attempt = state.get("attempt", 0) + 1
        started = time.perf_counter()
        detection_json: str | None = None
        generation_error: dict[str, str] | None = None
        plan: DetectionPlan | None = None
        strategy_context = (
            retrieve_strategy_clusters(
                strategy_catalog,
                _strategy_evidence_text(state),
                limit=workflow_config.strategy_limit,
            )
            if strategy_catalog is not None
            else []
        )
        try:
            if chat_model is None:
                chat_model = model_factory()
            extractor_kwargs: dict[str, Any] = {
                "model": chat_model,
                "previous_plan": state.get("detection_json"),
                "feedback": state.get("repair_feedback"),
            }
            if strategy_context:
                extractor_kwargs["strategy_context"] = strategy_context
            detection_json = feature_extractor(
                state["base"],
                state["poc"],
                state["http_request"],
                state["http_response"],
                **extractor_kwargs,
            )
            plan = parse_detection_json(detection_json)
        except Exception as exc:
            code = (
                "DETECTION_SCHEMA_ERROR"
                if detection_json is not None
                else "MODEL_GENERATION_ERROR"
            )
            generation_error = {"code": code, "message": _error_text(exc)}

        record: AttemptRecord = {
            "attempt": attempt,
            "detection_json": detection_json,
            "generation_error": generation_error,
            "generation_ms": round((time.perf_counter() - started) * 1_000),
            "compilation_ms": 0,
            "validation_ms": 0,
            "candidates": [],
            "selected_candidate": None,
            "selected_rule": None,
            "validation": None,
            "diagnosis": None,
            "final_judgment": None,
            "selected_rule_ir": None,
            "strategy_context": strategy_context,
        }
        attempts = _upsert_attempt(state.get("attempts", []), record)
        try:
            _persist_attempt(state["output_dir"], record)
        except OSError as exc:
            return {
                "attempt": attempt,
                "attempts": attempts,
                "status": "failed",
                "failure_code": "ARTIFACT_WRITE_ERROR",
                "failure_message": _error_text(exc),
            }

        if generation_error is not None:
            can_retry = attempt < workflow_config.max_rule_attempts
            return {
                "attempt": attempt,
                "attempts": attempts,
                "detection_json": detection_json,
                "detection_plan": None,
                "candidate_results": [],
                "selected_candidate": None,
                "repair_feedback": {
                    "failure_type": generation_error["code"],
                    "suggestion": generation_error["message"],
                },
                "validation_result": None,
                "strategy_context": strategy_context,
                "status": "running" if can_retry else "failed",
                "failure_code": None if can_retry else generation_error["code"],
                "failure_message": None if can_retry else generation_error["message"],
            }
        return {
            "attempt": attempt,
            "attempts": attempts,
            "detection_json": detection_json,
            "detection_plan": plan,
            "candidate_results": [],
            "selected_candidate": None,
            "repair_feedback": None,
            "validation_result": None,
            "strategy_context": strategy_context,
            "status": "running",
            "failure_code": None,
            "failure_message": None,
        }

    def evaluate_candidates_node(state: GenState) -> dict[str, Any]:
        nonlocal chat_model
        plan = state.get("detection_plan")
        if plan is None:
            return {
                "status": "failed",
                "failure_code": "DETECTION_PLAN_MISSING",
                "failure_message": "候选特征计划不存在",
            }
        deterministic_samples = [
            sample
            for sample in state.get("traffic_samples", [])
            if sample.source != "semantic"
        ]
        deterministic_skips = [
            item
            for item in state.get("mutation_skips", [])
            if item.get("content_type") != "semantic/testcase"
        ]
        try:
            semantic_samples = semantic_materializer(
                Path(state["output_dir"]) / workflow_config.sample_dirname,
                state["http_request"],
                state["http_response"],
                plan.semantic_testcases,
                config=workflow_config.pcap,
                sample_offset=len(deterministic_samples),
            )
        except Exception as exc:
            return {
                "status": "failed",
                "failure_code": "SEMANTIC_TESTCASE_BUILD_ERROR",
                "failure_message": _error_text(exc),
            }
        evaluation_samples = [*deterministic_samples, *semantic_samples]
        mutation_skips = [
            *deterministic_skips,
            *(
                skip.public_dict()
                for skip in getattr(semantic_samples, "mutation_skips", ())
            ),
        ]
        sample_matrix = [sample.public_dict() for sample in evaluation_samples]
        attempt = state["attempt"]
        record = dict(state["attempts"][-1])
        candidate_results: list[dict[str, Any]] = []
        compiled_by_index: dict[int, Any] = {}
        compile_started = time.perf_counter()
        for index, candidate in enumerate(plan.candidates, start=1):
            other_candidates = (
                *plan.candidates[: index - 1],
                *plan.candidates[index:],
            )
            unique_atoms = sorted(novel_evidence(candidate, other_candidates))
            item: dict[str, Any] = {
                "candidate_index": index,
                "evaluation_sid": workflow_config.sid_start + index - 1,
                "role": candidate.role,
                "detection_scope": candidate.detection_scope,
                "selection_tier": (
                    "primary"
                    if candidate.detection_scope == "case_specific"
                    else "supplemental"
                ),
                "reason": candidate.reason,
                "expected_tradeoff": CANDIDATE_ROLE_GUIDANCE[candidate.role],
                "evidence_fingerprint": evidence_fingerprint(candidate),
                "evidence_fingerprint_id": evidence_fingerprint_id(candidate),
                "novel_evidence": [
                    {"buffer": buffer, "value": value}
                    for buffer, value in unique_atoms
                ],
                "plan": asdict(candidate),
                "rule": None,
                "final_rule": None,
                "supplemental_final_rule": None,
                "supplemental_rule_ir": None,
                "supplemental_delivery_error": None,
                "final_sid": None,
                "delivered": False,
                "compile_error": None,
                "lint_issues": [],
                "complexity": None,
                "validation": None,
                "reference_metrics": None,
                "score": None,
                "passed": False,
                "selected": False,
                "rule_ir": None,
            }
            try:
                compiled = compile_candidate(
                    candidate,
                    sid=workflow_config.sid_start + index - 1,
                    candidate_index=index,
                    msg_prefix=state.get("case_id", "case"),
                )
                compiled_rule_ir = rule_ir_to_dict(
                    parse_suricata_rule(compiled.rule)
                )
            except RuleLintError as exc:
                item["compile_error"] = _error_text(exc)
                item["lint_issues"] = [asdict(issue) for issue in exc.issues]
            except Exception as exc:
                item["compile_error"] = _error_text(exc)
            else:
                compiled_by_index[index] = compiled
                item["rule"] = compiled.rule
                item["complexity"] = asdict(compiled.complexity)
                item["rule_ir"] = compiled_rule_ir
            candidate_results.append(item)
        compilation_ms = round((time.perf_counter() - compile_started) * 1_000)

        runtime = state["runtime_check"]
        validation_started = time.perf_counter()
        compiled_items = [compiled_by_index[index] for index in sorted(compiled_by_index)]
        if compiled_items:
            batch_rules = "\n".join(item.rule for item in compiled_items)
            evaluation_policy = RulePolicy(
                sid_start=None,
                require_contiguous_sids=False,
                positive_match_mode="any",
                max_rules=3,
            )
            batch_validation = matrix_validator(
                batch_rules,
                evaluation_samples,
                policy=evaluation_policy,
                suricata_bin=runtime["suricata_bin"],
                config_path=runtime["config_path"],
                syntax_timeout=workflow_config.syntax_timeout,
                replay_timeout=workflow_config.replay_timeout,
            )
            # 某个候选的 PCRE 若仍被 Suricata 拒绝，单独加载以隔离坏候选。
            isolate_syntax = (
                batch_validation.get("error_code") == "RULE_LOAD_ERROR"
                and len(compiled_items) > 1
            )
            for item in candidate_results:
                candidate_index = int(item["candidate_index"])
                compiled = compiled_by_index.get(candidate_index)
                if compiled is None:
                    continue
                if isolate_syntax:
                    raw_validation = matrix_validator(
                        compiled.rule,
                        evaluation_samples,
                        policy=RulePolicy(
                            sid_start=compiled.sid,
                            require_contiguous_sids=True,
                            positive_match_mode="any",
                            max_rules=1,
                        ),
                        suricata_bin=runtime["suricata_bin"],
                        config_path=runtime["config_path"],
                        syntax_timeout=workflow_config.syntax_timeout,
                        replay_timeout=workflow_config.replay_timeout,
                    )
                else:
                    raw_validation = batch_validation
                validation = _candidate_validation(
                    raw_validation,
                    compiled.sid,
                    direction=plan.candidates[candidate_index - 1].direction,
                )
                item["validation"] = validation
                item["reference_metrics"] = _candidate_reference_metrics(
                    validation, item["complexity"]
                )
                # 兼容旧 API 消费方；该值明确没有最终决策权。
                item["score"] = item["reference_metrics"]["heuristic_rank_value"]
                item["passed"] = validation["passed"]
        validation_ms = round((time.perf_counter() - validation_started) * 1_000)

        passing_primary = [
            item
            for item in candidate_results
            if item.get("detection_scope") == "case_specific" and item.get("passed")
        ]
        final_judgment: dict[str, Any] | None = None
        selected: dict[str, Any] | None
        if len(passing_primary) == 1:
            selected = passing_primary[0]
            final_judgment = {
                "selected_candidate": selected["candidate_index"],
                "reason": "唯一通过全部确定性门禁的主规则候选",
                "overfitting_risks": [],
                "source": "deterministic_single_candidate",
            }
        elif len(passing_primary) > 1:
            try:
                if chat_model is None:
                    chat_model = model_factory()
                judgment = candidate_judge(
                    base=state["base"],
                    poc=state["poc"],
                    request=state["http_request"],
                    response=state["http_response"],
                    candidates=passing_primary,
                    model=chat_model,
                )
                selected = next(
                    item
                    for item in passing_primary
                    if int(item["candidate_index"]) == judgment.selected_candidate
                )
                final_judgment = {
                    **judgment.public_dict(),
                    "source": "llm_final_judge",
                }
            except Exception as exc:
                selected = _deterministic_primary_fallback(passing_primary)
                final_judgment = {
                    "selected_candidate": (
                        selected.get("candidate_index") if selected else None
                    ),
                    "reason": "Final Judge 不可用，按覆盖事实与最低复杂度确定性降级",
                    "overfitting_risks": [],
                    "source": "deterministic_fallback",
                    "judge_error": _error_text(exc),
                }
        else:
            selected = _deterministic_primary_fallback(candidate_results)

        selected_rule: str | None = None
        selected_validation: RuleValidationResult | None = None
        selected_index: int | None = None
        selected_rule_ir: dict[str, Any] | None = None
        supplemental_rule_lines: list[str] = []
        supplemental_rule_irs: list[dict[str, Any]] = []
        if selected is not None:
            selected_index = int(selected["candidate_index"])
            selected_candidate_plan = plan.candidates[selected_index - 1]
            final_compiled = compile_candidate(
                selected_candidate_plan,
                sid=workflow_config.sid_start,
                candidate_index=selected_index,
                msg_prefix=state.get("case_id", "case"),
            )
            selected_rule = final_compiled.rule
            selected_rule_ir = rule_ir_to_dict(parse_suricata_rule(selected_rule))
            selected["final_rule"] = selected_rule
            selected["selected"] = True
            source_sid = workflow_config.sid_start + selected_index - 1
            selected_validation = _remap_validation_sid(
                selected["validation"], source_sid, workflow_config.sid_start
            )
            for item in candidate_results:
                item["final_sid"] = (
                    workflow_config.sid_start
                    if int(item["candidate_index"]) == selected_index
                    else None
                )

            if selected_validation["passed"]:
                selected["delivered"] = True
                next_delivery_sid = workflow_config.sid_start + 1
                for item in candidate_results:
                    if (
                        item.get("selection_tier") != "supplemental"
                        or not item.get("passed")
                    ):
                        continue
                    candidate_index = int(item["candidate_index"])
                    try:
                        supplemental_compiled = compile_candidate(
                            plan.candidates[candidate_index - 1],
                            sid=next_delivery_sid,
                            candidate_index=candidate_index,
                            msg_prefix=state.get("case_id", "case"),
                        )
                        supplemental_ir = rule_ir_to_dict(
                            parse_suricata_rule(supplemental_compiled.rule)
                        )
                    except Exception as exc:
                        item["supplemental_delivery_error"] = _error_text(exc)
                        continue
                    item["supplemental_final_rule"] = supplemental_compiled.rule
                    item["supplemental_rule_ir"] = supplemental_ir
                    item["final_sid"] = next_delivery_sid
                    item["delivered"] = True
                    supplemental_rule_lines.append(supplemental_compiled.rule)
                    supplemental_rule_irs.append(supplemental_ir)
                    next_delivery_sid += 1

        supplemental_rules = "\n".join(supplemental_rule_lines)

        record.update(
            {
                "compilation_ms": compilation_ms,
                "validation_ms": validation_ms,
                "candidates": candidate_results,
                "selected_candidate": selected_index,
                "selected_rule": selected_rule,
                "validation": selected_validation,
                "final_judgment": final_judgment,
                "selected_rule_ir": selected_rule_ir,
                "supplemental_rules": supplemental_rules,
                "supplemental_rule_irs": supplemental_rule_irs,
                "strategy_context": state.get("strategy_context", []),
            }
        )
        attempts = _upsert_attempt(state.get("attempts", []), record)
        try:
            _persist_attempt(state["output_dir"], record)
        except OSError as exc:
            return {
                "attempts": attempts,
                "status": "failed",
                "failure_code": "ARTIFACT_WRITE_ERROR",
                "failure_message": _error_text(exc),
            }

        if selected_validation is not None and selected_validation["passed"]:
            return {
                "attempts": attempts,
                "candidate_results": candidate_results,
                "selected_candidate": selected_index,
                "rules": selected_rule,
                "validation_result": selected_validation,
                "final_judgment": final_judgment,
                "traffic_samples": evaluation_samples,
                "sample_matrix": sample_matrix,
                "mutation_skips": mutation_skips,
                "selected_rule_ir": selected_rule_ir,
                "supplemental_rules": supplemental_rules,
                "supplemental_rule_irs": supplemental_rule_irs,
                "strategy_context": state.get("strategy_context", []),
                "status": "passed",
                "failure_code": None,
                "failure_message": None,
            }

        if selected_validation is None:
            code = "ALL_CANDIDATES_REJECTED"
            message = "所有候选都未通过确定性编译或规则质量检查"
            retryable = True
        else:
            code = selected_validation.get("error_code") or "CANDIDATE_VALIDATION_FAILED"
            message = "; ".join(selected_validation.get("errors", [])) or code
            retryable = bool(selected_validation.get("retryable"))
        can_retry = retryable and attempt < workflow_config.max_rule_attempts
        return {
            "attempts": attempts,
            "candidate_results": candidate_results,
            "selected_candidate": selected_index,
            "rules": selected_rule or state.get("rules", ""),
            "validation_result": selected_validation,
            "final_judgment": final_judgment,
            "traffic_samples": evaluation_samples,
            "sample_matrix": sample_matrix,
            "mutation_skips": mutation_skips,
            "selected_rule_ir": selected_rule_ir,
            "supplemental_rules": supplemental_rules,
            "supplemental_rule_irs": supplemental_rule_irs,
            "strategy_context": state.get("strategy_context", []),
            "status": "running" if can_retry else "failed",
            "failure_code": None if can_retry else code,
            "failure_message": None if can_retry else message,
        }

    def diagnose_failure_node(state: GenState) -> dict[str, Any]:
        record = dict(state["attempts"][-1])
        validation = state.get("validation_result")
        selected_index = state.get("selected_candidate")
        try:
            if validation is None or selected_index is None or not state.get("rules"):
                diagnosis: dict[str, Any] = {
                    "failure_type": "QUALITY_LINT_REJECTED",
                    "suspected_reason": "候选未通过确定性编译或质量检查",
                    "suggestion": "移除动态字段和弱结构特征，并补充真实利用值",
                    "failed_samples": [],
                    "diagnostics": [],
                }
            else:
                plan = state.get("detection_plan")
                candidate_plan = (
                    plan.candidates[selected_index - 1] if plan is not None else None
                )
                diagnosis = failure_diagnoser(
                    state["rules"],
                    validation,
                    state["traffic_samples"],
                    candidate_plan=candidate_plan,
                )
        except Exception as exc:
            diagnosis = {
                "failure_type": "DIAGNOSIS_ERROR",
                "suspected_reason": _error_text(exc),
                "suggestion": "根据逐样本 FN/FP 结果重新选择更稳定的特征",
                "failed_samples": [],
                "diagnostics": [],
            }
        record["diagnosis"] = diagnosis
        attempts = _upsert_attempt(state.get("attempts", []), record)
        try:
            _persist_attempt(state["output_dir"], record)
        except OSError as exc:
            return {
                "attempts": attempts,
                "status": "failed",
                "failure_code": "ARTIFACT_WRITE_ERROR",
                "failure_message": _error_text(exc),
            }
        feedback = _repair_feedback(
            diagnosis,
            validation
            if validation is not None
            else {
                "passed": False,
                "sample_results": [],
                "positive_coverage": 0.0,
                "false_positive_count": 0,
            },  # type: ignore[arg-type]
            state["traffic_samples"],
            state.get("candidate_results", []),
        )
        return {
            "attempts": attempts,
            "repair_feedback": feedback,
            "status": "running",
        }

    def persist_node(state: GenState) -> dict[str, Any]:
        output_dir = Path(state["output_dir"])
        try:
            output_dir.mkdir(parents=True, exist_ok=True)
            updates: dict[str, Any] = {}
            if state.get("rules"):
                filename = (
                    "generated.rules"
                    if state.get("status") == "passed"
                    else "failed-candidate.rules"
                )
                rules_path = output_dir / filename
                _atomic_write_text(rules_path, state["rules"] + "\n")
                updates["rules_path"] = str(rules_path)

            if state.get("status") == "passed" and state.get("supplemental_rules"):
                supplemental_rules_path = output_dir / "supplemental.rules"
                _atomic_write_text(
                    supplemental_rules_path,
                    str(state["supplemental_rules"]).rstrip() + "\n",
                )
                updates["supplemental_rules_path"] = str(
                    supplemental_rules_path
                )
                _write_json(
                    output_dir / "supplemental.rule-ir.json",
                    {"rules": state.get("supplemental_rule_irs", [])},
                )

            _write_json(output_dir / "traffic-matrix.json", state.get("sample_matrix", []))
            mutation_report = {
                "skip_count": len(state.get("mutation_skips", [])),
                "mutation_skips": state.get("mutation_skips", []),
            }
            _write_json(output_dir / "traffic-mutations.json", mutation_report)
            if state.get("selected_rule_ir") is not None:
                ir_filename = (
                    "generated.rule-ir.json"
                    if state.get("status") == "passed"
                    else "failed-candidate.rule-ir.json"
                )
                _write_json(
                    output_dir / ir_filename,
                    {"rules": [state["selected_rule_ir"]]},
                )
            if state.get("final_judgment") is not None:
                _write_json(
                    output_dir / "final-judgment.json",
                    state["final_judgment"],
                )
            report = {
                "case_id": state.get("case_id", "case"),
                "status": state.get("status", "failed"),
                "attempt": state.get("attempt", 0),
                "selected_candidate": state.get("selected_candidate"),
                "pcap": Path(state["pcap_path"]).name if state.get("pcap_path") else None,
                "rules": Path(updates["rules_path"]).name if updates.get("rules_path") else None,
                "supplemental_rules": (
                    Path(updates["supplemental_rules_path"]).name
                    if updates.get("supplemental_rules_path")
                    else None
                ),
                "failure_code": state.get("failure_code"),
                "failure_message": state.get("failure_message"),
                "sample_matrix": state.get("sample_matrix", []),
                "mutation_skips": state.get("mutation_skips", []),
                "rule_ir": state.get("selected_rule_ir"),
                "supplemental_rule_ir": state.get("supplemental_rule_irs", []),
                "final_judgment": state.get("final_judgment"),
                "strategy_context": state.get("strategy_context", []),
                "validation": state.get("validation_result"),
                "attempts": state.get("attempts", []),
            }
            report_path = output_dir / "validation-report.json"
            _write_json(report_path, report)
            updates["report_path"] = str(report_path)
            return updates
        except OSError as exc:
            return {
                "status": "failed",
                "failure_code": "ARTIFACT_WRITE_ERROR",
                "failure_message": _error_text(exc),
            }

    def route_after_step(state: GenState) -> Literal["continue", "stop"]:
        return "stop" if state.get("status") == "failed" else "continue"

    def route_after_extraction(
        state: GenState,
    ) -> Literal["evaluate", "retry", "stop"]:
        if state.get("status") == "failed":
            return "stop"
        return "evaluate" if state.get("detection_plan") is not None else "retry"

    def route_after_evaluation(
        state: GenState,
    ) -> Literal["diagnose", "done"]:
        return "diagnose" if state.get("status") == "running" else "done"

    builder = StateGraph(GenState)
    builder.add_node("preflight", preflight_node)
    builder.add_node("build_samples", build_samples_node)
    builder.add_node("extract_features", extract_features_node)
    builder.add_node("evaluate_candidates", evaluate_candidates_node)
    builder.add_node("diagnose_failure", diagnose_failure_node)
    builder.add_node("persist", persist_node)

    builder.add_edge(START, "preflight")
    builder.add_conditional_edges(
        "preflight",
        route_after_step,
        {"continue": "build_samples", "stop": "persist"},
    )
    builder.add_conditional_edges(
        "build_samples",
        route_after_step,
        {"continue": "extract_features", "stop": "persist"},
    )
    builder.add_conditional_edges(
        "extract_features",
        route_after_extraction,
        {
            "evaluate": "evaluate_candidates",
            "retry": "extract_features",
            "stop": "persist",
        },
    )
    builder.add_conditional_edges(
        "evaluate_candidates",
        route_after_evaluation,
        {"diagnose": "diagnose_failure", "done": "persist"},
    )
    builder.add_edge("diagnose_failure", "extract_features")
    builder.add_edge("persist", END)
    return builder.compile()


def run_generation(
    *,
    base: str,
    poc: str,
    http_request: str | bytes,
    http_response: str | bytes,
    output_dir: str | Path,
    model: ChatModel | None = None,
    case_id: str = "case",
    negative_pcap_paths: Sequence[str | Path] = (),
    config: WorkflowConfig | None = None,
) -> GenState:
    """让一个检测案例完整运行一次工作流。"""
    if not base.strip():
        raise ValueError("base 不能为空")
    if not poc.strip():
        raise ValueError("poc 不能为空")
    if not http_request:
        raise ValueError("http_request 不能为空")

    graph = build_workflow(model, config=config)
    return graph.invoke(
        {
            "case_id": case_id,
            "base": base,
            "poc": poc,
            "http_request": http_request,
            "http_response": http_response,
            "output_dir": str(output_dir),
            "negative_pcap_paths": [str(path) for path in negative_pcap_paths],
            "attempt": 0,
            "attempts": [],
            "status": "running",
        }
    )


def _case_input(case: dict[str, Any], key: str, case_dir: Path) -> str | bytes:
    path_value = case.get(f"{key}_path")
    if path_value:
        path = Path(path_value)
        if not path.is_absolute():
            path = case_dir / path
        return path.read_bytes()
    value = case.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f"{key} 必须是字符串，或通过 {key}_path 指向文件")
    return value


def _case_paths(values: Sequence[str], case_dir: Path) -> list[str]:
    paths: list[str] = []
    for value in values:
        path = Path(value)
        if not path.is_absolute():
            path = case_dir / path
        paths.append(str(path))
    return paths


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="运行 E Direct Generate -> Execute -> Repair -> Verify 主链"
    )
    parser.add_argument("case", type=Path, help="JSON 格式的检测案例")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--sid-start", type=int, default=123)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--suricata-bin", default=os.getenv("SURICATA_BIN"))
    parser.add_argument("--suricata-config", default=os.getenv("SURICATA_CONFIG"))
    parser.add_argument(
        "--ruleops-store",
        type=Path,
        default=Path(os.getenv("RULEOPS_STORE", "artifacts/rule-kb.json")),
    )
    return parser.parse_args()


def main() -> int:
    from production import (
        PIPELINE_ID,
        WorkflowConfig as DirectWorkflowConfig,
        run_generation as run_direct_generation,
    )

    args = _parse_args()
    case_path = args.case.resolve()
    case = json.loads(case_path.read_text(encoding="utf-8"))
    config = DirectWorkflowConfig(
        sid_start=args.sid_start,
        max_rule_attempts=args.max_attempts,
        suricata_bin=args.suricata_bin,
        suricata_config=args.suricata_config,
        ruleops_path=str(args.ruleops_store.resolve()),
    )
    python_poc = _case_input(case, "python_poc", case_path.parent)
    python_poc_path = case.get("python_poc_path")
    python_poc_filename = (
        Path(str(python_poc_path)).name
        if python_poc_path
        else str(case.get("python_poc_filename", "poc.py"))
    )
    result = run_direct_generation(
        case_id=str(case.get("case_id", case_path.stem)),
        base=str(case.get("base", "")),
        poc=str(case.get("poc", "")),
        http_request=_case_input(case, "http_request", case_path.parent),
        http_response=_case_input(case, "http_response", case_path.parent),
        python_poc=python_poc,
        python_poc_filename=python_poc_filename,
        negative_pcap_paths=_case_paths(
            case.get("negative_pcap_paths", []),
            case_path.parent,
        ),
        output_dir=args.output_dir,
        config=config,
    )
    summary = {
        key: result.get(key)
        for key in (
            "status",
            "attempt",
            "pcap_path",
            "rules_path",
            "report_path",
            "failure_code",
            "failure_message",
        )
    }
    summary.update(
        {
            "pipeline": PIPELINE_ID,
            "pipeline_id": PIPELINE_ID,
            "explanation": result.get("explanation"),
            "ruleops": result.get("ruleops"),
        }
    )
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if result.get("status") == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
