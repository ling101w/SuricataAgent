"""为 Suricata 规则生成工作流提供本地 Web 界面和任务 API。"""

from __future__ import annotations

import base64
import binascii
import difflib
import hashlib
import os
import re
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

from fastapi import FastAPI, HTTPException, Query, Response, status
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from production import PIPELINE_ID, WorkflowConfig, build_workflow
from poc_http_extractor import PocHttpExtractionError, extract_http_request
from ruleops import RuleOpsStore
from validate_rules import check_suricata_runtime


PROJECT_DIR = Path(__file__).resolve().parent
WEB_DIR = PROJECT_DIR / "web"
ARTIFACT_ROOT = Path(
    os.getenv("AGENT_ARTIFACT_DIR", str(PROJECT_DIR / "artifacts"))
).resolve()

MAX_HTTP_BYTES = 4 * 1024 * 1024
MAX_PYTHON_POC_BYTES = 1024 * 1024
MAX_NEGATIVE_PCAP_BYTES = 16 * 1024 * 1024
MAX_NEGATIVE_PCAPS = 4
MAX_RECENT_RUNS = 20
MAX_PENDING_RUNS = 8

STAGE_ORDER = (
    "preflight",
    "prepare",
    "generate",
    "execute",
    "repair",
    "verify",
    "parse_ir",
    "ruleops",
    "persist",
)
STAGE_LABELS = {
    "preflight": "环境预检",
    "prepare": "准备流量矩阵",
    "generate": "直接生成规则",
    "execute": "执行 Repair 样本",
    "repair": "运行时反馈修复",
    "verify": "完整矩阵验证",
    "parse_ir": "后置解析 Rule IR",
    "ruleops": "写入 RuleOps",
    "persist": "保存产物",
    "done": "完成",
}
NEXT_STAGE = {
    "preflight": "prepare",
    "prepare": "generate",
    "generate": "execute",
    "execute": "repair",
    "repair": "execute",
    "verify": "parse_ir",
    "parse_ir": "ruleops",
    "ruleops": "persist",
    "persist": "done",
}
SAFE_FILENAME_RE = re.compile(r"[^A-Za-z0-9._-]+")


class EncodedInput(BaseModel):
    """可直接传 UTF-8 文本，也可传保真的 Base64 字节。"""

    encoding: Literal["utf8", "base64"] = "utf8"
    content: str = Field(max_length=6 * 1024 * 1024)
    filename: str | None = Field(default=None, max_length=160)


class NegativePcapInput(BaseModel):
    """浏览器上传的反向流量样本。"""

    filename: str = Field(min_length=1, max_length=160)
    content_base64: str = Field(max_length=24 * 1024 * 1024)


class RunOptions(BaseModel):
    """允许从界面调整的有限工作流参数。"""

    sid_start: int = Field(default=123, ge=1, le=4_294_967_295)
    max_attempts: int = Field(default=3, ge=1, le=5)


class RunRequest(BaseModel):
    """创建一次规则生成任务所需的输入。"""

    case_id: str = Field(default="case", min_length=1, max_length=80)
    base: str = Field(min_length=1, max_length=30_000)
    poc: str = Field(default="", max_length=100_000)
    input_mode: Literal["http", "python_poc"] = "http"
    http_request: EncodedInput = Field(
        default_factory=lambda: EncodedInput(content="")
    )
    http_response: EncodedInput = Field(
        default_factory=lambda: EncodedInput(content="")
    )
    python_poc: EncodedInput | None = None
    negative_pcaps: list[NegativePcapInput] = Field(
        default_factory=list,
        max_length=MAX_NEGATIVE_PCAPS,
    )
    options: RunOptions = Field(default_factory=RunOptions)


class PocExtractionRequest(BaseModel):
    python_poc: EncodedInput


app = FastAPI(
    title="Suricata Rule Lab",
    version="1.0.0",
    docs_url="/api/docs",
    openapi_url="/api/openapi.json",
)
app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")

_jobs: dict[str, dict[str, Any]] = {}
_jobs_lock = threading.RLock()
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="rule-lab")


def _now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _safe_filename(value: str, fallback: str) -> str:
    filename = Path(value).name.strip()
    filename = SAFE_FILENAME_RE.sub("_", filename).strip("._")
    return filename[:120] or fallback


def _decode_http(value: EncodedInput, field_name: str) -> str | bytes:
    if value.encoding == "utf8":
        encoded = value.content.encode("utf-8")
        if len(encoded) > MAX_HTTP_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"{field_name} 超过 {MAX_HTTP_BYTES // 1024 // 1024} MiB 限制",
            )
        return value.content

    try:
        decoded = base64.b64decode(value.content, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=422,
            detail=f"{field_name} 不是有效的 Base64 数据",
        ) from exc
    if len(decoded) > MAX_HTTP_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"{field_name} 超过 {MAX_HTTP_BYTES // 1024 // 1024} MiB 限制",
        )
    return decoded


def _decode_python_poc(value: EncodedInput) -> tuple[str | bytes, str]:
    source = _decode_http(value, "Python PoC")
    size = len(source) if isinstance(source, bytes) else len(source.encode("utf-8"))
    if size > MAX_PYTHON_POC_BYTES:
        raise HTTPException(status_code=413, detail="Python PoC 超过 1 MiB 限制")
    filename = _safe_filename(value.filename or "poc.py", "poc.py")
    if not filename.casefold().endswith(".py"):
        filename += ".py"
    return source, filename


def _decode_negative_pcaps(
    values: list[NegativePcapInput],
) -> list[tuple[str, bytes]]:
    decoded_files: list[tuple[str, bytes]] = []
    total_size = 0
    for index, value in enumerate(values, start=1):
        try:
            content = base64.b64decode(value.content_base64, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise HTTPException(
                status_code=422,
                detail=f"反向 PCAP {index} 不是有效的 Base64 数据",
            ) from exc
        if len(content) > MAX_NEGATIVE_PCAP_BYTES:
            raise HTTPException(
                status_code=413,
                detail=f"反向 PCAP {index} 超过 16 MiB 限制",
            )
        total_size += len(content)
        if total_size > MAX_NEGATIVE_PCAP_BYTES * 2:
            raise HTTPException(status_code=413, detail="反向 PCAP 总大小超过 32 MiB 限制")
        filename = _safe_filename(value.filename, f"negative-{index}.pcap")
        decoded_files.append((filename, content))
    return decoded_files


def _new_progress() -> list[dict[str, Any]]:
    return [
        {
            "id": stage,
            "label": STAGE_LABELS[stage],
            "status": "pending",
            "runs": 0,
        }
        for stage in STAGE_ORDER
    ]


def _create_job(
    case_id: str,
    options: RunOptions,
    *,
    input_mode: Literal["http", "python_poc"] = "http",
) -> dict[str, Any]:
    job_id = uuid.uuid4().hex
    timestamp = _now()
    job = {
        "job_id": job_id,
        "case_id": case_id,
        "input_mode": input_mode,
        "status": "queued",
        "stage": "preflight",
        "attempt": 0,
        "max_attempts": options.max_attempts,
        "created_at": timestamp,
        "started_at": None,
        "finished_at": None,
        "failure_code": None,
        "failure_message": None,
        "rules": None,
        "validation": None,
        "selected_candidate": None,
        "sample_matrix": [],
        "mutation_skips": [],
        "final_judgment": None,
        "rule_ir": None,
        "explanation": None,
        "ruleops": None,
        "poc_extraction": None,
        "pipeline": PIPELINE_ID,
        "pipeline_id": PIPELINE_ID,
        "attempts": [],
        "progress": _new_progress(),
        "events": [],
        "artifact_paths": {},
        "artifact_dtos": [],
        "output_dir": ARTIFACT_ROOT / job_id,
    }
    with _jobs_lock:
        _jobs[job_id] = job
    return job


def _get_job(job_id: str) -> dict[str, Any]:
    with _jobs_lock:
        job = _jobs.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="任务不存在或服务已重启")
        return job


def _progress_item(job: dict[str, Any], stage: str) -> dict[str, Any]:
    return next(item for item in job["progress"] if item["id"] == stage)


def _mark_job_started(job_id: str) -> None:
    with _jobs_lock:
        job = _jobs[job_id]
        job["status"] = "running"
        job["started_at"] = _now()
        job["stage"] = "preflight"
        _progress_item(job, "preflight")["status"] = "running"


def _record_node(job_id: str, node: str, state: dict[str, Any]) -> None:
    with _jobs_lock:
        job = _jobs[job_id]
        current_status = state.get("status", "running")
        item = _progress_item(job, node)
        item["runs"] += 1

        terminal_failure_nodes = {"preflight", "prepare", "generate", "execute", "repair"}
        failed_here = current_status == "failed" and node in terminal_failure_nodes
        if node == "execute" and current_status == "running":
            validation = state.get("execute_validation") or {}
            if validation.get("passed"):
                next_stage = "verify"
            elif state.get("attempt", 0) < job["max_attempts"]:
                next_stage = "repair"
            else:
                next_stage = "verify"
        else:
            next_stage = "persist" if failed_here else NEXT_STAGE.get(node, "done")

        if node == "repair" and not failed_here:
            item["status"] = "retrying"
        elif node == "verify" and current_status == "failed":
            item["status"] = "failed"
        elif node == "parse_ir" and state.get("rule_ir_error"):
            item["status"] = "failed"
        elif node == "ruleops" and current_status == "passed" and not (
            state.get("ruleops") or {}
        ).get("indexed", False):
            item["status"] = "failed"
        else:
            item["status"] = "failed" if failed_here else "done"

        if next_stage in STAGE_ORDER:
            _progress_item(job, next_stage)["status"] = "running"

        job["stage"] = next_stage
        job["attempt"] = state.get("attempt", job["attempt"])
        job["failure_code"] = state.get("failure_code")
        job["failure_message"] = state.get("failure_message")
        if state.get("rules"):
            job["rules"] = state["rules"]
        if state.get("validation_result"):
            job["validation"] = _validation_summary(state["validation_result"])
        elif state.get("execute_validation"):
            job["validation"] = _validation_summary(state["execute_validation"])
        job["selected_candidate"] = state.get(
            "selected_candidate", job["selected_candidate"]
        )
        if state.get("sample_matrix"):
            job["sample_matrix"] = [dict(item) for item in state["sample_matrix"]]
        if "mutation_skips" in state:
            job["mutation_skips"] = [
                dict(item) for item in state.get("mutation_skips", [])
            ]
        if state.get("final_judgment") is not None:
            job["final_judgment"] = dict(state["final_judgment"])
        if state.get("selected_rule_ir") is not None:
            job["rule_ir"] = dict(state["selected_rule_ir"])
        if state.get("explanation") is not None:
            job["explanation"] = dict(state["explanation"])
        if state.get("ruleops") is not None:
            job["ruleops"] = dict(state["ruleops"])
        if state.get("poc_extraction") is not None:
            job["poc_extraction"] = dict(state["poc_extraction"])
        if state.get("attempts"):
            job["attempts"] = _attempt_summaries(state["attempts"])
        job["events"].append(
            {
                "stage": node,
                "label": STAGE_LABELS[node],
                "status": item["status"],
                "attempt": state.get("attempt", 0),
                "time": _now(),
            }
        )


def _validation_summary(value: dict[str, Any]) -> dict[str, Any]:
    allowed_fields = (
        "passed",
        "validation_level",
        "completed_stages",
        "failed_stage",
        "error_code",
        "retryable",
        "syntax_ok",
        "positive_match_ok",
        "negative_match_ok",
        "expected_sids",
        "positive_matched_sids",
        "negative_matched_sids",
        "sample_results",
        "positive_coverage",
        "false_positive_count",
        "quality_warnings",
        "errors",
        "warnings",
        "command_output",
    )
    summary = {key: value.get(key) for key in allowed_fields}
    command_output = summary.get("command_output")
    if isinstance(command_output, str):
        summary["command_output"] = command_output[-6_000:]
    return summary


def _rule_diff(previous: str | None, current: str | None) -> str:
    if not previous or not current or previous == current:
        return ""
    previous_lines = previous.replace("; ", ";\n").splitlines()
    current_lines = current.replace("; ", ";\n").splitlines()
    return "\n".join(
        difflib.unified_diff(
            previous_lines,
            current_lines,
            fromfile="上一轮",
            tofile="本轮",
            lineterm="",
        )
    )


def _attempt_summaries(values: list[dict[str, Any]]) -> list[dict[str, Any]]:
    summaries: list[dict[str, Any]] = []
    previous_rule: str | None = None
    for value in values:
        if value.get("kind") in {"generate", "repair"}:
            selected_rule = value.get("rule")
            summaries.append(
                {
                    "attempt": value.get("attempt"),
                    "kind": value.get("kind"),
                    "generation_ms": value.get("model_ms", 0),
                    "compilation_ms": 0,
                    "validation_ms": value.get("execution_ms", 0),
                    "selected_candidate": None,
                    "selected_rule": selected_rule,
                    "rule_diff": value.get("rule_diff")
                    or _rule_diff(previous_rule, selected_rule),
                    "validation": (
                        _validation_summary(value["validation"])
                        if isinstance(value.get("validation"), dict)
                        else None
                    ),
                    "feedback": value.get("feedback"),
                    "error": value.get("error"),
                    "candidates": [],
                }
            )
            if isinstance(selected_rule, str) and selected_rule:
                previous_rule = selected_rule
            continue
        candidates: list[dict[str, Any]] = []
        for candidate in value.get("candidates", []):
            candidates.append(
                {
                    key: candidate.get(key)
                    for key in (
                        "candidate_index",
                        "evaluation_sid",
                        "final_sid",
                        "role",
                        "detection_scope",
                        "selection_tier",
                        "reason",
                        "expected_tradeoff",
                        "evidence_fingerprint",
                        "evidence_fingerprint_id",
                        "novel_evidence",
                        "rule",
                        "final_rule",
                        "supplemental_final_rule",
                        "supplemental_rule_ir",
                        "supplemental_delivery_error",
                        "delivered",
                        "compile_error",
                        "lint_issues",
                        "complexity",
                        "reference_metrics",
                        "score",
                        "passed",
                        "selected",
                        "rule_ir",
                    )
                }
                | {
                    "validation": (
                        _validation_summary(candidate["validation"])
                        if isinstance(candidate.get("validation"), dict)
                        else None
                    )
                }
            )
        selected_rule = value.get("selected_rule")
        summary = {
            "attempt": value.get("attempt"),
            "generation_error": value.get("generation_error"),
            "generation_ms": value.get("generation_ms", 0),
            "compilation_ms": value.get("compilation_ms", 0),
            "validation_ms": value.get("validation_ms", 0),
            "selected_candidate": value.get("selected_candidate"),
            "selected_rule": selected_rule,
            "rule_diff": _rule_diff(previous_rule, selected_rule),
            "validation": (
                _validation_summary(value["validation"])
                if isinstance(value.get("validation"), dict)
                else None
            ),
            "diagnosis": value.get("diagnosis"),
            "final_judgment": value.get("final_judgment"),
            "selected_rule_ir": value.get("selected_rule_ir"),
            "strategy_context": value.get("strategy_context", []),
            "candidates": candidates,
        }
        summaries.append(summary)
        if isinstance(selected_rule, str) and selected_rule:
            previous_rule = selected_rule
    return summaries


def _file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _collect_artifacts(job: dict[str, Any]) -> None:
    output_dir = Path(job["output_dir"]).resolve()
    candidates = {
        "pcap": output_dir / "traffic.pcap",
        "rules": output_dir / "generated.rules",
        "report": output_dir / "validation-report.json",
        "mutations": output_dir / "traffic-mutations.json",
        "rule_ir": output_dir / "generated.rule-ir.json",
        "supplemental_rules": output_dir / "supplemental.rules",
        "supplemental_rule_ir": output_dir / "supplemental.rule-ir.json",
        "final_judgment": output_dir / "final-judgment.json",
        "coverage_graph": output_dir / "coverage-graph.json",
        "python_poc": output_dir / "poc-source.py",
        "poc_extraction": output_dir / "poc-extraction.json",
        "extracted_request": output_dir / "selected-request.raw",
        "http_candidates": output_dir / "http-candidates.json",
        "extraction_report": output_dir / "extraction-report.json",
    }
    if not candidates["rules"].is_file():
        candidates["rules"] = output_dir / "failed-candidate.rules"
    if not candidates["rule_ir"].is_file():
        candidates["rule_ir"] = output_dir / "failed-candidate.rule-ir.json"

    artifact_paths: dict[str, Path] = {}
    for kind, path in candidates.items():
        resolved = path.resolve()
        try:
            resolved.relative_to(output_dir)
        except ValueError:
            continue
        if resolved.is_file():
            artifact_paths[kind] = resolved
    job["artifact_paths"] = artifact_paths
    job["artifact_dtos"] = [
        _artifact_dto(job["job_id"], kind, path)
        for kind, path in artifact_paths.items()
    ]


def _finish_job(job_id: str, state: dict[str, Any]) -> None:
    with _jobs_lock:
        job = _jobs[job_id]
        final_status = state.get("status", "failed")
        job["status"] = final_status if final_status in {"passed", "failed"} else "failed"
        job["stage"] = "done"
        job["attempt"] = state.get("attempt", job["attempt"])
        job["finished_at"] = _now()
        job["failure_code"] = state.get("failure_code")
        job["failure_message"] = state.get("failure_message")
        if state.get("rules"):
            job["rules"] = state["rules"]
        if state.get("validation_result"):
            job["validation"] = _validation_summary(state["validation_result"])
        job["selected_candidate"] = state.get(
            "selected_candidate", job["selected_candidate"]
        )
        if state.get("sample_matrix"):
            job["sample_matrix"] = [dict(item) for item in state["sample_matrix"]]
        if "mutation_skips" in state:
            job["mutation_skips"] = [
                dict(item) for item in state.get("mutation_skips", [])
            ]
        if state.get("final_judgment") is not None:
            job["final_judgment"] = dict(state["final_judgment"])
        if state.get("selected_rule_ir") is not None:
            job["rule_ir"] = dict(state["selected_rule_ir"])
        if state.get("explanation") is not None:
            job["explanation"] = dict(state["explanation"])
        if state.get("ruleops") is not None:
            job["ruleops"] = dict(state["ruleops"])
        if state.get("poc_extraction") is not None:
            job["poc_extraction"] = dict(state["poc_extraction"])
        if state.get("attempts"):
            job["attempts"] = _attempt_summaries(state["attempts"])
        _collect_artifacts(job)


def _fail_job(job_id: str, code: str, message: str) -> None:
    with _jobs_lock:
        job = _jobs[job_id]
        active_stage = job.get("stage")
        if active_stage in STAGE_ORDER:
            _progress_item(job, active_stage)["status"] = "failed"
        job["status"] = "failed"
        job["stage"] = "done"
        job["failure_code"] = code
        job["failure_message"] = message[:2_000]
        job["finished_at"] = _now()
        _collect_artifacts(job)


def _write_negative_pcaps(
    output_dir: Path,
    values: list[tuple[str, bytes]],
) -> list[str]:
    if not values:
        return []
    input_dir = output_dir / "negative-inputs"
    input_dir.mkdir(parents=True, exist_ok=True)
    paths: list[str] = []
    used_names: set[str] = set()
    for index, (filename, content) in enumerate(values, start=1):
        candidate = filename
        if candidate in used_names:
            stem = Path(filename).stem
            suffix = Path(filename).suffix or ".pcap"
            candidate = f"{stem}-{index}{suffix}"
        used_names.add(candidate)
        path = input_dir / candidate
        path.write_bytes(content)
        paths.append(str(path))
    return paths


def _run_generation_job(
    job_id: str,
    payload: RunRequest,
    request_data: str | bytes,
    response_data: str | bytes,
    python_poc_data: str | bytes,
    python_poc_filename: str,
    negative_pcaps: list[tuple[str, bytes]],
) -> None:
    _mark_job_started(job_id)
    try:
        job = _get_job(job_id)
        output_dir = Path(job["output_dir"])
        output_dir.mkdir(parents=True, exist_ok=True)
        negative_paths = _write_negative_pcaps(output_dir, negative_pcaps)
        config = WorkflowConfig(
            sid_start=payload.options.sid_start,
            max_rule_attempts=payload.options.max_attempts,
            ruleops_path=str(ARTIFACT_ROOT / "rule-kb.json"),
        )
        graph = build_workflow(config=config)
        state: dict[str, Any] = {
            "case_id": payload.case_id,
            "base": payload.base,
            "poc": payload.poc,
            "input_mode": payload.input_mode,
            "http_request": request_data,
            "http_response": response_data,
            "python_poc": python_poc_data,
            "python_poc_filename": python_poc_filename,
            "output_dir": str(output_dir),
            "negative_pcap_paths": negative_paths,
            "attempt": 0,
            "attempts": [],
            "status": "running",
        }

        for update in graph.stream(state, stream_mode="updates"):
            for node, values in update.items():
                if not isinstance(values, dict):
                    continue
                state.update(values)
                _record_node(job_id, node, state)
        _finish_job(job_id, state)
    except Exception as exc:
        message = str(exc).strip() or exc.__class__.__name__
        _fail_job(job_id, "WEB_RUNNER_ERROR", message)


def _artifact_dto(job_id: str, kind: str, path: Path) -> dict[str, Any]:
    return {
        "kind": kind,
        "name": path.name,
        "size": path.stat().st_size,
        "sha256": _file_sha256(path),
        "download_url": f"/api/runs/{job_id}/artifacts/{kind}",
    }


def _public_job(job: dict[str, Any]) -> dict[str, Any]:
    return {
        "job_id": job["job_id"],
        "case_id": job["case_id"],
        "input_mode": job["input_mode"],
        "pipeline": job["pipeline"],
        "pipeline_id": job["pipeline_id"],
        "status": job["status"],
        "stage": job["stage"],
        "stage_label": STAGE_LABELS.get(job["stage"], job["stage"]),
        "attempt": job["attempt"],
        "max_attempts": job["max_attempts"],
        "created_at": job["created_at"],
        "started_at": job["started_at"],
        "finished_at": job["finished_at"],
        "failure": (
            {
                "code": job["failure_code"],
                "message": job["failure_message"],
            }
            if job["failure_code"] or job["failure_message"]
            else None
        ),
        "rules": job["rules"],
        "selected_candidate": job["selected_candidate"],
        "validation": job["validation"],
        "sample_matrix": [dict(item) for item in job["sample_matrix"]],
        "mutation_skips": [dict(item) for item in job["mutation_skips"]],
        "final_judgment": job["final_judgment"],
        "rule_ir": job["rule_ir"],
        "explanation": job["explanation"],
        "ruleops": job["ruleops"],
        "poc_extraction": job["poc_extraction"],
        "attempts": [dict(item) for item in job["attempts"]],
        "progress": [dict(item) for item in job["progress"]],
        "events": [dict(item) for item in job["events"][-30:]],
        "artifacts": [dict(item) for item in job["artifact_dtos"]],
    }


@app.get("/", include_in_schema=False)
def index() -> FileResponse:
    return FileResponse(WEB_DIR / "index.html")


@app.get("/favicon.ico", include_in_schema=False, status_code=204)
def favicon() -> Response:
    return Response(status_code=204)


@app.get("/api/runtime")
def runtime_status(response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    runtime = check_suricata_runtime()
    model_api_key = os.getenv("LLM_API_KEY") or os.getenv("DEEPSEEK_API_KEY")
    model_base_url = os.getenv("LLM_BASE_URL") or os.getenv("DEEPSEEK_BASE_URL")
    model_name = os.getenv("LLM_MODEL") or os.getenv("DEEPSEEK_MODEL")
    model_offline = os.getenv("LLM_OFFLINE", "").strip().casefold() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return {
        "pipeline": PIPELINE_ID,
        "pipeline_id": PIPELINE_ID,
        "suricata": {
            "ok": runtime["ok"],
            "error_code": runtime["error_code"],
            "message": runtime["message"],
        },
        "model": {
            "configured": bool(
                model_api_key and model_base_url and model_name and not model_offline
            ),
            "provider": os.getenv("LLM_PROVIDER", "openai_compatible"),
            "endpoint_host": urlsplit(model_base_url).hostname if model_base_url else None,
            "name": model_name,
            "offline": model_offline,
        },
        "limits": {
            "http_bytes": MAX_HTTP_BYTES,
            "python_poc_bytes": MAX_PYTHON_POC_BYTES,
            "negative_pcap_bytes": MAX_NEGATIVE_PCAP_BYTES,
            "negative_pcap_count": MAX_NEGATIVE_PCAPS,
        },
    }


@app.post("/api/runs", status_code=status.HTTP_202_ACCEPTED)
def create_run(payload: RunRequest) -> dict[str, Any]:
    if not payload.base.strip():
        raise HTTPException(status_code=422, detail="漏洞信息不能为空")
    request_data = _decode_http(payload.http_request, "HTTP 请求")
    response_data = _decode_http(payload.http_response, "HTTP 响应")
    python_poc_data: str | bytes = ""
    python_poc_filename = "poc.py"
    if payload.python_poc is not None:
        python_poc_data, python_poc_filename = _decode_python_poc(payload.python_poc)
    if payload.input_mode == "http" and not request_data:
        raise HTTPException(status_code=422, detail="HTTP 请求不能为空")
    if payload.input_mode == "python_poc" and not python_poc_data:
        raise HTTPException(status_code=422, detail="Python PoC 不能为空")
    if not payload.poc.strip() and not python_poc_data:
        raise HTTPException(status_code=422, detail="PoC 信息不能为空")
    negative_pcaps = _decode_negative_pcaps(payload.negative_pcaps)

    # 检查队列和插入任务必须位于同一锁区间，避免并发请求同时越过上限。
    with _jobs_lock:
        pending_count = sum(
            job["status"] in {"queued", "running"} for job in _jobs.values()
        )
        if pending_count >= MAX_PENDING_RUNS:
            raise HTTPException(status_code=429, detail="当前排队任务过多，请稍后再试")
        job = _create_job(
            payload.case_id.strip() or "case",
            payload.options,
            input_mode=payload.input_mode,
        )
    _executor.submit(
        _run_generation_job,
        job["job_id"],
        payload,
        request_data,
        response_data,
        python_poc_data,
        python_poc_filename,
        negative_pcaps,
    )
    return {
        "job_id": job["job_id"],
        "status": "queued",
        "status_url": f"/api/runs/{job['job_id']}",
    }


@app.post("/api/poc/extract")
def extract_poc_http(payload: PocExtractionRequest, response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    source, filename = _decode_python_poc(payload.python_poc)
    if not source:
        raise HTTPException(status_code=422, detail="Python PoC 不能为空")
    try:
        return extract_http_request(source, filename=filename).public_dict()
    except PocHttpExtractionError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": exc.code, "message": str(exc)},
        ) from exc


@app.get("/api/runs")
def list_runs(response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    with _jobs_lock:
        jobs = sorted(
            _jobs.values(),
            key=lambda value: value["created_at"],
            reverse=True,
        )[:MAX_RECENT_RUNS]
        return {"runs": [_public_job(job) for job in jobs]}


@app.get("/api/runs/{job_id}")
def get_run(job_id: str, response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    with _jobs_lock:
        return _public_job(_get_job(job_id))


@app.get("/api/ruleops")
def ruleops_overview(
    response: Response,
    q: str | None = Query(default=None, max_length=160),
) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    return RuleOpsStore(ARTIFACT_ROOT / "rule-kb.json").overview(q)


@app.get("/api/ruleops/rules/{record_id}")
def ruleops_record(record_id: str, response: Response) -> dict[str, Any]:
    response.headers["Cache-Control"] = "no-store"
    record = RuleOpsStore(ARTIFACT_ROOT / "rule-kb.json").get_record(record_id)
    if record is None:
        raise HTTPException(status_code=404, detail="Rule KB record 不存在")
    return record


@app.get("/api/runs/{job_id}/artifacts/{kind}")
def download_artifact(
    job_id: str,
    kind: Literal[
        "pcap",
        "rules",
        "supplemental_rules",
        "report",
        "mutations",
        "rule_ir",
        "supplemental_rule_ir",
        "final_judgment",
        "coverage_graph",
        "python_poc",
        "poc_extraction",
        "extracted_request",
        "http_candidates",
        "extraction_report",
    ],
):
    with _jobs_lock:
        job = _get_job(job_id)
        path = job["artifact_paths"].get(kind)
        if path is None or not path.is_file():
            raise HTTPException(status_code=404, detail="产物尚未生成或不存在")
    media_types = {
        "pcap": "application/vnd.tcpdump.pcap",
        "rules": "text/plain; charset=utf-8",
        "supplemental_rules": "text/plain; charset=utf-8",
        "report": "application/json",
        "mutations": "application/json",
        "rule_ir": "application/json",
        "supplemental_rule_ir": "application/json",
        "final_judgment": "application/json",
        "coverage_graph": "application/json",
        "python_poc": "text/x-python; charset=utf-8",
        "poc_extraction": "application/json",
        "extracted_request": "application/http",
        "http_candidates": "application/json",
        "extraction_report": "application/json",
    }
    return FileResponse(
        path,
        media_type=media_types[kind],
        filename=path.name,
        headers={"X-Content-Type-Options": "nosniff"},
    )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(
        "web_app:app",
        host=os.getenv("WEB_HOST", "127.0.0.1"),
        port=int(os.getenv("WEB_PORT", "8000")),
        reload=False,
    )
