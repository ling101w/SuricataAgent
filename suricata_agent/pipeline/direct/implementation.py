"""Compatibility facade for the split direct pipeline implementation."""

from .artifacts import explain_result
from .graph import PIPELINE_ID, PIPELINE_VERSION, build_workflow, run_generation
from .nodes import (
    constraint_rejection_validation,
    create_nodes,
    error_text,
    feedback,
    policy,
    response_text,
    split_samples,
)
from .prompts import (
    DIRECT_REPAIR_SYSTEM_PROMPT,
    DIRECT_SYSTEM_PROMPT,
    prompt_hashes,
    render_evidence,
)
from .state import ChatModel, DirectAttempt, DirectState, WorkflowConfig


_error_text = error_text
_response_text = response_text
_evidence = render_evidence
_policy = policy
_feedback = feedback
_constraint_rejection_validation = constraint_rejection_validation


__all__ = [
    "DIRECT_REPAIR_SYSTEM_PROMPT",
    "DIRECT_SYSTEM_PROMPT",
    "PIPELINE_ID",
    "PIPELINE_VERSION",
    "ChatModel",
    "DirectAttempt",
    "DirectState",
    "WorkflowConfig",
    "build_workflow",
    "create_nodes",
    "explain_result",
    "prompt_hashes",
    "run_generation",
    "split_samples",
]
