"""Backward-compatible import shim for the production direct workflow.

The implementation now lives under
``suricata_agent.pipeline.direct.implementation``. New code should import the
public contract from ``production`` or ``suricata_agent.pipeline.direct.graph``.
"""

from __future__ import annotations

from suricata_agent.pipeline.direct import implementation as _implementation

PIPELINE_ID = _implementation.PIPELINE_ID
PIPELINE_VERSION = _implementation.PIPELINE_VERSION
DIRECT_SYSTEM_PROMPT = _implementation.DIRECT_SYSTEM_PROMPT
DIRECT_REPAIR_SYSTEM_PROMPT = _implementation.DIRECT_REPAIR_SYSTEM_PROMPT
DirectState = _implementation.DirectState
WorkflowConfig = _implementation.WorkflowConfig
build_workflow = _implementation.build_workflow
explain_result = _implementation.explain_result
prompt_hashes = _implementation.prompt_hashes
run_generation = _implementation.run_generation
split_samples = _implementation.split_samples


def __getattr__(name: str):
    return getattr(_implementation, name)


__all__ = [
    "DIRECT_REPAIR_SYSTEM_PROMPT",
    "DIRECT_SYSTEM_PROMPT",
    "PIPELINE_ID",
    "PIPELINE_VERSION",
    "DirectState",
    "WorkflowConfig",
    "build_workflow",
    "explain_result",
    "prompt_hashes",
    "run_generation",
    "split_samples",
]
