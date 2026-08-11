"""LangGraph assembly and public execution entrypoint for E-direct."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from langgraph.graph import END, START, StateGraph

from .nodes import create_nodes, split_samples
from .state import ChatModel, DirectState, WorkflowConfig


PIPELINE_ID = "E-direct-repair-v1"
PIPELINE_VERSION = PIPELINE_ID


def build_workflow(
    model: ChatModel | None = None,
    *,
    config: WorkflowConfig | None = None,
    model_factory=None,
    runtime_checker=None,
    traffic_builder=None,
    matrix_validator=None,
    ruleops_factory=None,
):
    """Build Generate -> Execute -> Repair -> Verify graph."""
    kwargs = {key: value for key, value in {"model_factory": model_factory, "runtime_checker": runtime_checker, "traffic_builder": traffic_builder, "matrix_validator": matrix_validator, "ruleops_factory": ruleops_factory}.items() if value is not None}
    nodes = create_nodes(model, config=config, **kwargs)
    builder = StateGraph(DirectState)
    for name in ("preflight", "prepare", "generate", "execute", "repair", "verify", "parse_ir", "ruleops", "persist"):
        builder.add_node(name, nodes[name])
    builder.add_edge(START, "preflight")
    builder.add_conditional_edges("preflight", nodes["stop_prepare"], {"prepare": "prepare", "persist": "persist"})
    builder.add_conditional_edges("prepare", nodes["stop_generate"], {"generate": "generate", "persist": "persist"})
    builder.add_conditional_edges("generate", nodes["stop_execute"], {"execute": "execute", "persist": "persist"})
    builder.add_conditional_edges("execute", nodes["after_execute"], {"repair": "repair", "verify": "verify", "persist": "persist"})
    builder.add_conditional_edges("repair", nodes["stop_repair"], {"execute": "execute", "persist": "persist"})
    builder.add_edge("verify", "parse_ir")
    builder.add_edge("parse_ir", "ruleops")
    builder.add_edge("ruleops", "persist")
    builder.add_edge("persist", END)
    return builder.compile()


def run_generation(
    *,
    base: str,
    poc: str,
    http_request: str | bytes = "",
    http_response: str | bytes = "",
    output_dir: str | Path,
    model: ChatModel | None = None,
    case_id: str = "case",
    python_poc: str | bytes = "",
    python_poc_filename: str = "poc.py",
    negative_pcap_paths: Sequence[str | Path] = (),
    config: WorkflowConfig | None = None,
) -> DirectState:
    if not base.strip():
        raise ValueError("base 不能为空")
    if not poc.strip() and not python_poc:
        raise ValueError("poc 或 python_poc 至少提供一个")
    if not http_request and not python_poc:
        raise ValueError("http_request 或 python_poc 至少提供一个")
    return build_workflow(model, config=config).invoke({
        "case_id": case_id,
        "base": base,
        "poc": poc,
        "http_request": http_request,
        "http_response": http_response,
        "python_poc": python_poc,
        "python_poc_filename": python_poc_filename,
        "input_mode": "python_poc" if python_poc else "http",
        "output_dir": str(Path(output_dir).resolve()),
        "negative_pcap_paths": [str(Path(item).resolve()) for item in negative_pcap_paths],
        "attempt": 0,
        "attempts": [],
        "status": "running",
    })


__all__ = ["PIPELINE_ID", "PIPELINE_VERSION", "DirectState", "WorkflowConfig", "build_workflow", "run_generation", "split_samples"]
