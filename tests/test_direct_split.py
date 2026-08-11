from __future__ import annotations

import re
from pathlib import Path

from generate_pcap import generate_pcap
from suricata_agent.pipeline.direct.graph import build_workflow
from suricata_agent.pipeline.direct.nodes import create_nodes
from suricata_agent.pipeline.direct.state import WorkflowConfig
from traffic_cases import TrafficSample, TrafficSampleList


INITIAL_RULE = 'alert http any any -> any any (flow:established,to_server; http.uri; content:"/download"; sid:123; rev:1;)'
REPAIRED_RULE = 'alert http any any -> any any (flow:established,to_server; http.uri; content:"/download"; http.uri; content:"../"; sid:123; rev:1;)'


class FakeResponse:
    def __init__(self, content: str) -> None:
        self.content = content


class FakeModel:
    def __init__(self) -> None:
        self.calls: list[str] = []

    def invoke(self, messages: list[object]) -> FakeResponse:
        prompt = str(getattr(messages[-1], "content", ""))
        self.calls.append(prompt)
        return FakeResponse(INITIAL_RULE if len(self.calls) == 1 else REPAIRED_RULE)


def validation(rules: str, samples: list[TrafficSample], **_kwargs: object):
    sids = [int(value) for value in re.findall(r"\bsid:(\d+)", rules)]
    repaired = 'content:"../"' in rules
    results = []
    for sample in samples:
        matched = sids if repaired and sample.expected == "alert" else []
        passed = bool(matched) if sample.expected == "alert" else not matched
        results.append({"name": sample.name, "expected": sample.expected, "reason": sample.reason, "validates": sample.validates, "expected_any_sids": sids, "matched_sids": matched, "passed": passed, "applicable": True})
    positives = [item for item in results if item["expected"] == "alert"]
    false_positives = [item for item in results if item["expected"] == "no_alert" and not item["passed"]]
    positive_passed = sum(bool(item["passed"]) for item in positives)
    passed = repaired and positive_passed == len(positives) and not false_positives
    return {"passed": passed, "validation_level": "sample_matrix", "completed_stages": ["static", "syntax"] + (["positive", "negative"] if passed else []), "failed_stage": None if passed else "positive", "error_code": None if passed else "POSITIVE_TRAFFIC_MISSED", "retryable": not passed, "syntax_ok": True, "positive_match_ok": passed, "negative_match_ok": True, "expected_sids": sids, "positive_matched_sids": sids if passed else [], "negative_matched_sids": [], "errors": [], "warnings": [], "command_output": "", "sample_results": results, "positive_coverage": positive_passed / len(positives), "false_positive_count": len(false_positives), "quality_warnings": []}


def test_node_factory_exposes_graph_contract() -> None:
    node_set = create_nodes(
        model=FakeModel(),
        runtime_checker=lambda **_kwargs: {"ok": True, "suricata_bin": "suricata", "config_path": "suricata.yaml", "error_code": None, "message": None},
    )
    assert set(node_set) == {"preflight", "prepare", "generate", "execute", "repair", "verify", "parse_ir", "ruleops", "persist", "stop_prepare", "stop_generate", "stop_execute", "stop_repair", "after_execute"}


def test_split_graph_preserves_direct_pipeline_behavior(tmp_path: Path) -> None:
    pcap = tmp_path / "sample.pcap"
    request = b"GET /download?path=../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"
    generate_pcap(str(pcap), request, b"HTTP/1.1 200 OK\r\n\r\n")
    samples = TrafficSampleList([
        TrafficSample("positive-original", "alert", "original", "original", pcap, request),
        TrafficSample("positive-visible", "alert", "visible variant", "derived", pcap, request),
        TrafficSample("negative-visible", "no_alert", "visible near miss", "derived", pcap, request),
        TrafficSample("positive-heldout", "alert", "verify only", "derived", pcap, request),
        TrafficSample("negative-heldout", "no_alert", "verify only", "derived", pcap, request),
    ])
    model = FakeModel()
    output = tmp_path / "artifacts" / "run-1"
    graph = build_workflow(
        model=model,
        config=WorkflowConfig(max_rule_attempts=3, ruleops_path=str(tmp_path / "artifacts" / "rule-kb.json")),
        runtime_checker=lambda **_kwargs: {"ok": True, "suricata_bin": "suricata", "config_path": "suricata.yaml", "error_code": None, "message": None},
        traffic_builder=lambda *_args, **_kwargs: samples,
        matrix_validator=validation,
    )
    state = graph.invoke({"case_id": "CVE-SPLIT-TEST", "base": "path traversal", "poc": "read /etc/passwd", "http_request": request, "http_response": b"HTTP/1.1 200 OK\r\n\r\nroot:x:0:0", "output_dir": str(output), "negative_pcap_paths": [], "attempt": 0, "attempts": [], "status": "running"})

    assert state["status"] == "passed"
    assert state["attempt"] == 2
    assert state["rules"] == REPAIRED_RULE
    assert state["selected_rule_ir"]["sid"] == 123
    assert state["explanation"]["verdict"] == "verified"
    assert "positive-heldout" not in model.calls[1]
    assert "negative-heldout" not in model.calls[1]
    assert {item["split"] for item in state["sample_matrix"]} == {"repair", "verify_only"}
    assert (output / "generated.rules").is_file()
    assert (output / "generated.rule-ir.json").is_file()
    assert (output / "validation-report.json").is_file()
