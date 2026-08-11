"""Generate, execute, repair, verify, and persistence nodes.

The factory keeps injectable collaborators explicit so tests and integrations can
replace model, traffic, runtime, validation, and RuleOps services independently.
"""

from __future__ import annotations

import json
import shutil
import time
from collections.abc import Callable, Sequence
from pathlib import Path
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from generate_tools import create_chat_model
from pcap_tcp_analysis import analyze_sample_pcaps, matrix_tcp_summary
from poc_http_extractor import PocHttpExtractionError, extract_http_request
from repair_constraints import RepairConstraints, accept_repair, compare_repair
from rule_ir import parse_suricata_rule, rule_ir_to_dict
from ruleops import RuleOpsStore
from traffic_cases import TrafficSample, build_traffic_matrix
from validate_rules import (
    RulePolicy,
    RuleValidationResult,
    SuricataRuntimeCheck,
    check_suricata_runtime,
    clean_rule_text,
    validate_rule_matrix,
)

from .artifacts import (
    atomic_bytes,
    atomic_text,
    explain_result,
    rule_diff,
    rule_sha256,
    sample_summary,
    write_json,
)
from .prompts import DIRECT_REPAIR_SYSTEM_PROMPT, DIRECT_SYSTEM_PROMPT, prompt_hashes, render_evidence
from .state import ChatModel, DirectAttempt, DirectState, WorkflowConfig


def error_text(error: Exception) -> str:
    return (str(error).strip() or error.__class__.__name__)[:2_000]


def response_text(response: object) -> str:
    content = getattr(response, "content", response)
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts: list[str] = []
        for item in content:
            if isinstance(item, str):
                parts.append(item)
            elif isinstance(item, dict) and isinstance(item.get("text"), str):
                parts.append(item["text"])
            elif isinstance(getattr(item, "text", None), str):
                parts.append(item.text)
        return "".join(parts)
    raise TypeError("模型返回了不支持的内容类型")


def constraint_rejection_validation(violations: Sequence[str]) -> RuleValidationResult:
    return {
        "passed": False,
        "validation_level": "repair_constraints",
        "completed_stages": [],
        "failed_stage": "repair_constraints",
        "error_code": "REPAIR_CONSTRAINT_VIOLATION",
        "retryable": True,
        "syntax_ok": None,
        "positive_match_ok": None,
        "negative_match_ok": None,
        "expected_sids": [],
        "positive_matched_sids": [],
        "negative_matched_sids": [],
        "errors": list(violations),
        "warnings": [],
        "command_output": "",
        "sample_results": [],
        "positive_coverage": 0.0,
        "false_positive_count": 0,
        "quality_warnings": ["Candidate was rejected before Suricata execution by repair constraints."],
    }


def split_samples(samples: Sequence[TrafficSample]) -> tuple[list[TrafficSample], list[TrafficSample]]:
    """Choose a deterministic repair set and keep all other samples held out."""
    original = next((sample for sample in samples if sample.name == "positive-original"), None)
    positives = [sample for sample in samples if sample.expected == "alert" and sample is not original]
    negatives = [sample for sample in samples if sample.expected == "no_alert"]
    repair: list[TrafficSample] = []
    if original is not None:
        repair.append(original)
    if positives:
        repair.append(positives[0])
    if negatives:
        repair.append(negatives[0])
    repair_ids = {id(sample) for sample in repair}
    return repair, [sample for sample in samples if id(sample) not in repair_ids]


def policy(config: WorkflowConfig) -> RulePolicy:
    return RulePolicy(
        sid_start=config.sid_start,
        require_contiguous_sids=True,
        allowed_protocols=frozenset({"http"}),
        allowed_directions=frozenset({"->"}),
        required_flow_options=frozenset({"established", "to_server"}),
        require_rev=True,
        max_rule_bytes=16 * 1024,
        max_content_count=24,
        max_pcre_count=2,
        max_pcre_bytes=1_024,
        max_byte_jump_count=0,
        positive_match_mode="all",
        max_rules=1,
    )


def feedback(validation: RuleValidationResult, samples: Sequence[TrafficSample]) -> dict[str, Any]:
    by_name = {str(item.get("name")): item for item in validation.get("sample_results", []) if isinstance(item, dict)}
    rendered = []
    for sample in samples:
        observed = by_name.get(sample.name, {})
        rendered.append({"name": sample.name, "expected": sample.expected, "reason": sample.reason, "passed": observed.get("passed"), "matched_sids": observed.get("matched_sids", []), "http_request": (sample.request or b"").decode("utf-8", errors="backslashreplace") if isinstance(sample.request, bytes) else (sample.request or "")})
    diagnostics = [line for line in str(validation.get("command_output", "")).splitlines() if "error" in line.casefold() or "failed" in line.casefold()]
    return {"syntax_ok": validation.get("syntax_ok"), "error_code": validation.get("error_code"), "errors": validation.get("errors", []), "syntax_diagnostics": diagnostics[-30:], "samples": rendered, "holdout_policy": "Verify-only samples are never visible to repair."}


def create_nodes(
    model: ChatModel | None = None,
    *,
    config: WorkflowConfig | None = None,
    model_factory: Callable[[], ChatModel] = create_chat_model,
    runtime_checker: Callable[..., SuricataRuntimeCheck] = check_suricata_runtime,
    traffic_builder: Callable[..., list[TrafficSample]] = build_traffic_matrix,
    matrix_validator: Callable[..., RuleValidationResult] = validate_rule_matrix,
    ruleops_factory: Callable[[str | Path], RuleOpsStore] = RuleOpsStore,
) -> dict[str, Callable[..., object]]:
    workflow_config = config or WorkflowConfig()
    chat_model = model

    def preflight_node(_: DirectState) -> dict[str, Any]:
        try:
            runtime = runtime_checker(suricata_bin=workflow_config.suricata_bin, config_path=workflow_config.suricata_config)
        except Exception as exc:
            return {"status": "failed", "failure_code": "SURICATA_PREFLIGHT_ERROR", "failure_message": error_text(exc)}
        if not runtime["ok"]:
            return {"runtime_check": runtime, "status": "failed", "failure_code": runtime.get("error_code") or "SURICATA_RUNTIME_ERROR", "failure_message": runtime.get("message") or "Suricata 不可用"}
        return {"runtime_check": runtime, "status": "running"}

    def prepare_node(state: DirectState) -> dict[str, Any]:
        try:
            missing = [item for item in state.get("negative_pcap_paths", []) if not Path(item).is_file()]
            if missing:
                raise FileNotFoundError(Path(missing[0]).name)
            output = Path(state["output_dir"])
            request_data = state.get("http_request", "")
            extraction_public: dict[str, Any] | None = None
            python_poc = state.get("python_poc", "")
            if python_poc:
                source_bytes = python_poc if isinstance(python_poc, bytes) else python_poc.encode("utf-8")
                extraction = extract_http_request(source_bytes, filename=state.get("python_poc_filename", "poc.py"))
                extraction_public = extraction.public_dict()
                extraction_public["selected_request_overridden"] = bool(request_data)
                atomic_bytes(output / "poc-source.py", source_bytes)
                write_json(output / "poc-extraction.json", extraction_public)
                write_json(output / "http-candidates.json", {"candidates": extraction_public["candidates"]})
                write_json(output / "extraction-report.json", {key: extraction_public[key] for key in ("adapter", "source_sha256", "filename", "candidate_count", "selected_index", "accepted", "minimum_confidence", "warnings", "selected_request_overridden")} | {"selected": extraction_public["selected"]})
                if not request_data:
                    if not extraction.accepted:
                        return {"poc_extraction": extraction_public, "status": "failed", "failure_code": "POC_HTTP_LOW_CONFIDENCE", "failure_message": "Python PoC 提取置信度不足；请检查并补全 Raw HTTP 请求"}
                    request_data = extraction.selected.raw_request
                selected_bytes = request_data if isinstance(request_data, bytes) else request_data.encode("utf-8")
                atomic_bytes(output / "selected-request.raw", selected_bytes)
            if not request_data:
                return {"status": "failed", "failure_code": "HTTP_EVIDENCE_MISSING", "failure_message": "必须提供 Raw HTTP 或可静态提取的 Python PoC"}
            samples = traffic_builder(Path(state["output_dir"]) / workflow_config.sample_dirname, request_data, state.get("http_response", ""), config=workflow_config.pcap, uploaded_negative_pcaps=tuple(state.get("negative_pcap_paths", [])))
            repair, heldout = split_samples(samples)
            if not repair or not any(item.expected == "alert" for item in repair):
                raise ValueError("无法构造 repair 正向样本")
            original = next(item for item in samples if item.name == "positive-original")
            compatibility = Path(state["output_dir"]) / workflow_config.pcap_filename
            compatibility.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(original.pcap_path, compatibility)
            repair_ids = {id(item) for item in repair}
            pcap_analysis = analyze_sample_pcaps(samples)
            tcp_by_sample = {item["sample_name"]: matrix_tcp_summary(item) for item in pcap_analysis["pcaps"]}
            matrix = []
            for item in samples:
                summary = sample_summary(item, "repair" if id(item) in repair_ids else "verify_only")
                summary["tcp"] = tcp_by_sample[item.name]
                matrix.append(summary)
            return {"traffic_samples": list(samples), "http_request": request_data, "poc_extraction": extraction_public, "repair_samples": repair, "heldout_samples": heldout, "sample_matrix": matrix, "pcap_analysis": pcap_analysis, "mutation_skips": [item.public_dict() for item in getattr(samples, "mutation_skips", ())], "pcap_path": str(compatibility), "status": "running"}
        except PocHttpExtractionError as exc:
            return {"status": "failed", "failure_code": exc.code, "failure_message": error_text(exc)}
        except Exception as exc:
            return {"status": "failed", "failure_code": "TRAFFIC_PREPARE_ERROR", "failure_message": error_text(exc)}

    def generate_node(state: DirectState) -> dict[str, Any]:
        nonlocal chat_model
        started = time.perf_counter()
        try:
            if chat_model is None:
                chat_model = model_factory()
            response = chat_model.invoke([SystemMessage(content=DIRECT_SYSTEM_PROMPT), HumanMessage(content=f"Use sid:{workflow_config.sid_start}. Generate the rule from this evidence:\n\n{render_evidence(state)}")])
            raw = response_text(response).strip()
            rule = clean_rule_text(raw)
            if not rule:
                raise ValueError("模型返回了空规则")
            attempt: DirectAttempt = {"attempt": 1, "kind": "generate", "rule": rule, "rule_sha256": rule_sha256(rule), "model_ms": round((time.perf_counter() - started) * 1_000), "execution_ms": 0, "validation": None, "feedback": None, "rule_diff": "", "constraint_violations": [], "accepted": True, "rejection_reasons": [], "acceptance_metrics": {}, "error": None}
            output = Path(state["output_dir"])
            atomic_text(output / "attempts" / "01-generate" / "model-response.txt", raw + "\n")
            atomic_text(output / "attempts" / "01-generate" / "output.rules", rule + "\n")
            return {"rules": rule, "initial_rule": rule, "attempt": 1, "attempts": [attempt], "status": "running"}
        except Exception as exc:
            return {"attempt": 1, "status": "failed", "failure_code": "MODEL_GENERATION_ERROR", "failure_message": error_text(exc)}

    def execute_node(state: DirectState) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            attempts = [dict(item) for item in state.get("attempts", [])]
            current = attempts[-1]
            violations = list(current.get("constraint_violations", []))
            validation = constraint_rejection_validation(violations) if current.get("kind") == "repair" and violations else matrix_validator(state["rules"], state["repair_samples"], policy=policy(workflow_config), suricata_bin=workflow_config.suricata_bin, config_path=workflow_config.suricata_config, syntax_timeout=workflow_config.syntax_timeout, replay_timeout=workflow_config.replay_timeout)
            current["execution_ms"] = round((time.perf_counter() - started) * 1_000)
            current["validation"] = validation
            active_rule = state["rules"]
            active_validation = validation
            if current.get("kind") == "repair":
                incumbent = next((item for item in reversed(attempts[:-1]) if item.get("accepted") is not False and isinstance(item.get("validation"), dict)), None)
                if incumbent is None:
                    raise ValueError("Repair 缺少已执行的基线规则")
                if violations:
                    accepted, rejection_reasons, acceptance_metrics = False, violations, {}
                else:
                    decision = accept_repair(incumbent["validation"], validation)
                    accepted, rejection_reasons, acceptance_metrics = decision.accepted, list(decision.reasons), decision.metrics
                current["accepted"] = accepted
                current["rejection_reasons"] = rejection_reasons
                current["acceptance_metrics"] = acceptance_metrics
                if not accepted:
                    active_rule, active_validation = str(incumbent["rule"]), incumbent["validation"]
            write_json(Path(state["output_dir"]) / "attempts" / f"{state['attempt']:02d}-{current.get('kind', 'attempt')}" / "execution.json", validation)
            return {"rules": active_rule, "execute_validation": active_validation, "attempts": attempts, "status": "running"}
        except Exception as exc:
            return {"status": "failed", "failure_code": "EXECUTION_ERROR", "failure_message": error_text(exc)}

    def repair_node(state: DirectState) -> dict[str, Any]:
        nonlocal chat_model
        previous = state["rules"]
        validation = state.get("execute_validation")
        if validation is None:
            return {"status": "failed", "failure_code": "REPAIR_FEEDBACK_MISSING", "failure_message": "Repair 缺少 Execute 结果"}
        feedback_data = feedback(validation, state["repair_samples"])
        constraints = RepairConstraints.from_rule(state.get("initial_rule", previous))
        started = time.perf_counter()
        attempt_number = state["attempt"] + 1
        try:
            if chat_model is None:
                chat_model = model_factory()
            task = ("Repair the current rule using only the vulnerability evidence and the runtime feedback below.\n\n" f"<evidence>\n{render_evidence(state)}\n</evidence>\n" f"<current_rule>\n{previous}\n</current_rule>\n" "<repair_constraints>\n" + json.dumps(constraints.public_dict(), ensure_ascii=False, indent=2) + "\n</repair_constraints>\n" "<runtime_feedback>\n" + json.dumps(feedback_data, ensure_ascii=False, indent=2) + "\n</runtime_feedback>")
            response = chat_model.invoke([SystemMessage(content=DIRECT_REPAIR_SYSTEM_PROMPT), HumanMessage(content=task)])
            raw = response_text(response).strip()
            repaired = clean_rule_text(raw)
            if not repaired:
                raise ValueError("模型返回了空 repair 规则")
            violations = list(compare_repair(constraints, repaired))
            attempt: DirectAttempt = {"attempt": attempt_number, "kind": "repair", "rule": repaired, "rule_sha256": rule_sha256(repaired), "model_ms": round((time.perf_counter() - started) * 1_000), "execution_ms": 0, "validation": None, "feedback": feedback_data, "rule_diff": rule_diff(previous, repaired), "constraint_violations": violations, "accepted": False, "rejection_reasons": [], "acceptance_metrics": {}, "error": None}
            attempt_dir = Path(state["output_dir"]) / "attempts" / f"{attempt_number:02d}-repair"
            atomic_text(attempt_dir / "input.rules", previous + "\n")
            write_json(attempt_dir / "feedback.json", feedback_data)
            atomic_text(attempt_dir / "model-response.txt", raw + "\n")
            atomic_text(attempt_dir / "output.rules", repaired + "\n")
            return {"rules": repaired, "attempt": attempt_number, "attempts": [*state.get("attempts", []), attempt], "execute_validation": None, "status": "running"}
        except Exception as exc:
            return {"status": "failed", "failure_code": "MODEL_REPAIR_ERROR", "failure_message": error_text(exc)}

    def verify_node(state: DirectState) -> dict[str, Any]:
        try:
            validation = matrix_validator(state["rules"], state["traffic_samples"], policy=policy(workflow_config), suricata_bin=workflow_config.suricata_bin, config_path=workflow_config.suricata_config, syntax_timeout=workflow_config.syntax_timeout, replay_timeout=workflow_config.replay_timeout)
            repair_attempts = sum(item.get("kind") == "repair" for item in state.get("attempts", []))
            explanation = explain_result(validation, repair_attempts=repair_attempts, heldout_names=[item.name for item in state.get("heldout_samples", [])])
            return {"validation_result": validation, "explanation": explanation, "status": "passed" if validation.get("passed") else "failed", "failure_code": None if validation.get("passed") else "FINAL_VERIFY_FAILED", "failure_message": None if validation.get("passed") else explanation["summary"]}
        except Exception as exc:
            return {"status": "failed", "failure_code": "FINAL_VERIFY_ERROR", "failure_message": error_text(exc), "explanation": explain_result(None, repair_attempts=0, heldout_names=())}

    def parse_ir_node(state: DirectState) -> dict[str, Any]:
        try:
            return {"selected_rule_ir": rule_ir_to_dict(parse_suricata_rule(state["rules"])), "rule_ir_error": None}
        except Exception as exc:
            return {"selected_rule_ir": None, "rule_ir_error": error_text(exc)}

    def ruleops_node(state: DirectState) -> dict[str, Any]:
        if state.get("status") != "passed" or state.get("selected_rule_ir") is None:
            return {"ruleops": {"indexed": False, "reason": "Only verified, parseable final rules enter Rule KB."}}
        try:
            store_path = workflow_config.ruleops_path or str(Path(state["output_dir"]).resolve().parent / "rule-kb.json")
            store = ruleops_factory(store_path)
            result = store.ingest(case_id=state["case_id"], rule=state["rules"], rule_ir=state["selected_rule_ir"], validation=state["validation_result"], sample_matrix=state.get("sample_matrix", []), artifact_dir=state["output_dir"])
            try:
                coverage = store.rebuild_case_coverage(state["case_id"], state["traffic_samples"], matrix_validator=matrix_validator, suricata_bin=workflow_config.suricata_bin, config_path=workflow_config.suricata_config, syntax_timeout=workflow_config.syntax_timeout, replay_timeout=workflow_config.replay_timeout)
                result["coverage"] = coverage
                write_json(Path(state["output_dir"]) / "coverage-graph.json", coverage)
            except Exception as exc:
                result["coverage"], result["coverage_error"] = None, error_text(exc)
            return {"ruleops": result}
        except Exception as exc:
            return {"ruleops": {"indexed": False, "reason": "RULEOPS_INDEX_ERROR", "error": error_text(exc)}}

    def persist_node(state: DirectState) -> dict[str, Any]:
        output = Path(state["output_dir"])
        try:
            output.mkdir(parents=True, exist_ok=True)
            rules_name = "generated.rules" if state.get("status") == "passed" else "failed-candidate.rules"
            rules_path = output / rules_name
            if state.get("rules"):
                atomic_text(rules_path, state["rules"].rstrip() + "\n")
            write_json(output / "traffic-matrix.json", state.get("sample_matrix", []))
            write_json(output / "pcap-analysis.json", state.get("pcap_analysis", {"version": 1, "summary": {"pcap_count": 0, "analyzed_pcaps": 0, "failed_pcaps": 0, "tcp_connections": 0, "multi_connection_pcaps": 0}, "pcaps": []}))
            write_json(output / "traffic-mutations.json", {"skip_count": len(state.get("mutation_skips", [])), "mutation_skips": state.get("mutation_skips", [])})
            if state.get("selected_rule_ir") is not None:
                write_json(output / "generated.rule-ir.json", state["selected_rule_ir"])
            elif state.get("rule_ir_error"):
                write_json(output / "generated.rule-ir-error.json", {"error": state["rule_ir_error"]})
            report = {"pipeline": "E-direct-repair-v1", "pipeline_id": "E-direct-repair-v1", "prompt_hashes": prompt_hashes(), "case_id": state.get("case_id"), "input_mode": state.get("input_mode", "http"), "poc_extraction": state.get("poc_extraction"), "status": state.get("status"), "attempt": state.get("attempt", 0), "repair_attempts": sum(item.get("kind") == "repair" for item in state.get("attempts", [])), "repair_sample_names": [item.name for item in state.get("repair_samples", [])], "verify_only_sample_names": [item.name for item in state.get("heldout_samples", [])], "failure_code": state.get("failure_code"), "failure_message": state.get("failure_message"), "validation": state.get("validation_result"), "pcap_analysis": state.get("pcap_analysis"), "explanation": state.get("explanation"), "rule_ir": state.get("selected_rule_ir"), "rule_ir_error": state.get("rule_ir_error"), "ruleops": state.get("ruleops"), "attempts": state.get("attempts", [])}
            report_path = output / "validation-report.json"
            write_json(report_path, report)
            return {"rules_path": str(rules_path) if state.get("rules") else "", "report_path": str(report_path)}
        except Exception as exc:
            return {"status": "failed", "failure_code": "ARTIFACT_WRITE_ERROR", "failure_message": error_text(exc)}

    def stop_or(next_node: str) -> Callable[[DirectState], str]:
        def route(state: DirectState) -> str:
            return "persist" if state.get("status") == "failed" else next_node
        return route

    def after_execute(state: DirectState) -> str:
        validation = state.get("execute_validation")
        if state.get("status") == "failed" or validation is None:
            return "persist"
        if validation.get("passed"):
            return "verify"
        if state.get("attempt", 0) < workflow_config.max_rule_attempts:
            return "repair"
        return "verify"

    return {"preflight": preflight_node, "prepare": prepare_node, "generate": generate_node, "execute": execute_node, "repair": repair_node, "verify": verify_node, "parse_ir": parse_ir_node, "ruleops": ruleops_node, "persist": persist_node, "stop_prepare": stop_or("prepare"), "stop_generate": stop_or("generate"), "stop_execute": stop_or("execute"), "stop_repair": stop_or("execute"), "after_execute": after_execute}


__all__ = ["constraint_rejection_validation", "create_nodes", "error_text", "feedback", "policy", "response_text", "split_samples"]
