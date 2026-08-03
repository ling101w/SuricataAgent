"""Canonical public entrypoint for the production Suricata pipeline.

Experimental and legacy workflows remain importable from their implementation
modules, but application code must import the production contract from here.
"""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from direct_workflow import (
    PIPELINE_ID,
    DirectState,
    WorkflowConfig,
    build_workflow,
    run_generation as _run_generation,
)


def run_generation(
    *,
    base: str,
    poc: str,
    http_request: str | bytes = "",
    http_response: str | bytes = "",
    output_dir: str | Path,
    model: object | None = None,
    case_id: str = "case",
    python_poc: str | bytes = "",
    python_poc_filename: str = "poc.py",
    negative_pcap_paths: Sequence[str | Path] = (),
    config: WorkflowConfig | None = None,
) -> DirectState:
    """Run the production pipeline and stamp its stable identity on the result."""
    result = _run_generation(
        base=base,
        poc=poc,
        http_request=http_request,
        http_response=http_response,
        output_dir=output_dir,
        model=model,
        case_id=case_id,
        python_poc=python_poc,
        python_poc_filename=python_poc_filename,
        negative_pcap_paths=negative_pcap_paths,
        config=config,
    )
    result["pipeline_id"] = PIPELINE_ID
    return result


__all__ = [
    "PIPELINE_ID",
    "DirectState",
    "WorkflowConfig",
    "build_workflow",
    "run_generation",
]
