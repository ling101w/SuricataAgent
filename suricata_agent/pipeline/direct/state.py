"""Typed state and runtime configuration for the direct workflow."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal, Protocol, TypedDict

from suricata_agent.services.suricata import RuleValidationResult, SuricataRuntimeCheck
from suricata_agent.traffic.pcap import PcapConfig
from suricata_agent.traffic.cases import TrafficSample


class ChatModel(Protocol):
    def invoke(self, messages: list[object]) -> object: ...


class DirectAttempt(TypedDict, total=False):
    attempt: int
    kind: Literal["generate", "repair"]
    rule: str
    rule_sha256: str
    model_ms: int
    execution_ms: int
    validation: RuleValidationResult | None
    feedback: dict[str, Any] | None
    rule_diff: str
    constraint_violations: list[str]
    accepted: bool
    rejection_reasons: list[str]
    acceptance_metrics: dict[str, object]
    error: str | None


class DirectState(TypedDict, total=False):
    pipeline_id: str
    case_id: str
    base: str
    poc: str
    http_request: str | bytes
    http_response: str | bytes
    python_poc: str | bytes
    python_poc_filename: str
    input_mode: Literal["http", "python_poc"]
    poc_extraction: dict[str, Any] | None
    output_dir: str
    negative_pcap_paths: list[str]
    runtime_check: SuricataRuntimeCheck
    traffic_samples: list[TrafficSample]
    repair_samples: list[TrafficSample]
    heldout_samples: list[TrafficSample]
    sample_matrix: list[dict[str, object]]
    pcap_analysis: dict[str, Any]
    mutation_skips: list[dict[str, str]]
    pcap_path: str
    rules: str
    initial_rule: str
    attempt: int
    attempts: list[DirectAttempt]
    execute_validation: RuleValidationResult | None
    validation_result: RuleValidationResult | None
    explanation: dict[str, Any] | None
    selected_rule_ir: dict[str, Any] | None
    rule_ir_error: str | None
    ruleops: dict[str, Any] | None
    status: Literal["running", "passed", "failed"]
    failure_code: str | None
    failure_message: str | None
    report_path: str
    rules_path: str


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
    ruleops_path: str | None = None
    pcap: PcapConfig = field(default_factory=PcapConfig)

    def __post_init__(self) -> None:
        if not 1 <= self.sid_start <= 4_294_967_295:
            raise ValueError("sid_start 必须是有效的 Suricata SID")
        if not 1 <= self.max_rule_attempts <= 5:
            raise ValueError("max_rule_attempts 必须在 1 到 5 之间")
        for name, value in (("pcap_filename", self.pcap_filename), ("sample_dirname", self.sample_dirname)):
            if not value or Path(value).name != value:
                raise ValueError(f"{name} 必须是单独的名称")


__all__ = ["ChatModel", "DirectAttempt", "DirectState", "WorkflowConfig"]
