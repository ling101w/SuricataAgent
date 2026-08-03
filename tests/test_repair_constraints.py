from __future__ import annotations

from pathlib import Path

from direct_workflow import WorkflowConfig, build_workflow
from repair_constraints import RepairConstraints, accept_repair, compare_repair
from traffic_cases import TrafficSample, TrafficSampleList


BASE_RULE = (
    'alert http any any -> any any (flow:established,to_server; '
    'http.uri; content:"/admin/upload"; sid:123; rev:1;)'
)
SAFE_REPAIR = (
    'alert http any any -> any any (flow:established,to_server; '
    'http.uri; content:"/admin/upload"; http.request_body; content:"../"; '
    'sid:123; rev:1;)'
)
BROAD_REPAIR = (
    'alert http any any -> any any (flow:established,to_server; '
    'http.request_body; content:"../"; sid:123; rev:1;)'
)


def _validation(
    *,
    syntax_ok: bool = True,
    rows: list[dict[str, object]],
) -> dict[str, object]:
    false_positives = sum(
        row["expected"] == "no_alert" and not row["passed"] for row in rows
    )
    return {
        "passed": syntax_ok and all(bool(row["passed"]) for row in rows),
        "syntax_ok": syntax_ok,
        "sample_results": rows,
        "false_positive_count": false_positives,
    }


def test_repair_constraints_preserve_header_flow_and_semantic_anchors() -> None:
    constraints = RepairConstraints.from_rule(BASE_RULE)

    assert compare_repair(constraints, SAFE_REPAIR) == ()
    assert any(
        "端点语义锚点" in reason
        for reason in compare_repair(constraints, BROAD_REPAIR)
    )
    assert any(
        "flow" in reason
        for reason in compare_repair(
            constraints,
            BASE_RULE.replace("flow:established,to_server; ", ""),
        )
    )
    assert any(
        "protocol" in reason
        for reason in compare_repair(
            constraints,
            BASE_RULE.replace("alert http", "alert tcp"),
        )
    )


def test_repair_constraints_allow_equivalent_header_spacing_and_pcre_anchor() -> None:
    constraints = RepairConstraints.from_rule(BASE_RULE)
    pcre_repair = (
        'alert  http any any  ->  any any (flow:established,to_server; '
        'http.uri; pcre:"/\\/admin\\/upload/U"; http.request_body; '
        'content:"../"; sid:123; rev:1;)'
    )

    assert compare_repair(constraints, pcre_repair) == ()


def test_repair_acceptance_rejects_regression_and_new_false_positive() -> None:
    before = _validation(
        rows=[
            {"name": "positive-original", "expected": "alert", "passed": True},
            {"name": "positive-variant", "expected": "alert", "passed": False},
            {"name": "negative-near-miss", "expected": "no_alert", "passed": True},
        ]
    )
    after = _validation(
        rows=[
            {"name": "positive-original", "expected": "alert", "passed": False},
            {"name": "positive-variant", "expected": "alert", "passed": True},
            {"name": "negative-near-miss", "expected": "no_alert", "passed": False},
        ]
    )

    decision = accept_repair(before, after)

    assert decision.accepted is False
    assert any("positive-original" in reason for reason in decision.reasons)
    assert any("误报增加" in reason for reason in decision.reasons)


def test_repair_acceptance_allows_no_regression_detection_gain() -> None:
    before = _validation(
        rows=[
            {"name": "positive-original", "expected": "alert", "passed": True},
            {"name": "positive-variant", "expected": "alert", "passed": False},
            {"name": "negative-near-miss", "expected": "no_alert", "passed": True},
        ]
    )
    after = _validation(
        rows=[
            {"name": "positive-original", "expected": "alert", "passed": True},
            {"name": "positive-variant", "expected": "alert", "passed": True},
            {"name": "negative-near-miss", "expected": "no_alert", "passed": True},
        ]
    )

    assert accept_repair(before, after).accepted is True


class _BroadRepairModel:
    def __init__(self) -> None:
        self.calls = 0

    def invoke(self, _messages: list[object]):
        self.calls += 1
        return type(
            "Response",
            (),
            {"content": BASE_RULE if self.calls == 1 else BROAD_REPAIR},
        )()


def test_workflow_does_not_execute_constraint_violating_repair(tmp_path: Path) -> None:
    pcap = tmp_path / "sample.pcap"
    pcap.write_bytes(b"pcap")
    request = b"POST /admin/upload HTTP/1.1\r\nHost: test\r\n\r\n../"
    samples = TrafficSampleList(
        [
            TrafficSample("positive-original", "alert", "original", "original", pcap, request),
            TrafficSample("positive-visible", "alert", "variant", "derived", pcap, request),
            TrafficSample("negative-visible", "no_alert", "near miss", "derived", pcap, request),
            TrafficSample("positive-heldout", "alert", "heldout", "derived", pcap, request),
        ]
    )
    executed_rules: list[str] = []

    def validator(rules: str, selected: list[TrafficSample], **_kwargs: object):
        executed_rules.append(rules)
        rows = [
            {
                "name": sample.name,
                "expected": sample.expected,
                "passed": sample.expected == "no_alert",
                "applicable": True,
            }
            for sample in selected
        ]
        value = _validation(rows=rows)
        return {
            **value,
            "validation_level": "sample_matrix",
            "completed_stages": ["static", "syntax"],
            "failed_stage": "samples",
            "error_code": "NO_POSITIVE_MATCH",
            "retryable": True,
            "positive_match_ok": False,
            "negative_match_ok": True,
            "expected_sids": [123],
            "positive_matched_sids": [],
            "negative_matched_sids": [],
            "errors": [],
            "warnings": [],
            "command_output": "",
            "positive_coverage": 0.0,
            "quality_warnings": [],
        }

    graph = build_workflow(
        model=_BroadRepairModel(),
        config=WorkflowConfig(max_rule_attempts=2),
        runtime_checker=lambda **_kwargs: {
            "ok": True,
            "suricata_bin": "suricata",
            "config_path": "suricata.yaml",
            "error_code": None,
            "message": None,
        },
        traffic_builder=lambda *_args, **_kwargs: samples,
        matrix_validator=validator,
    )

    state = graph.invoke(
        {
            "case_id": "CVE-CONSTRAINT",
            "base": "upload traversal",
            "poc": "upload ../",
            "http_request": request,
            "http_response": "",
            "output_dir": str(tmp_path / "artifacts"),
            "negative_pcap_paths": [],
            "attempt": 0,
            "attempts": [],
            "status": "running",
        }
    )

    assert BROAD_REPAIR not in executed_rules
    assert state["rules"] == BASE_RULE
    assert state["attempts"][1]["accepted"] is False
    assert state["attempts"][1]["constraint_violations"]
