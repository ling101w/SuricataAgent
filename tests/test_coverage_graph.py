from __future__ import annotations

from typing import Literal

import pytest

from coverage_graph import RuleProfile, analyze_coverage, analyze_rule_coverage


def _profile(
    sid: int,
    fingerprint: str,
    *,
    complexity: int,
    pcre_count: int = 0,
    text: str | None = None,
    logic_fingerprint: str | None = None,
    direction: Literal["request", "response"] = "request",
    detection_scope: Literal[
        "case_specific", "exploit_family", "success_indicator"
    ] = "case_specific",
) -> RuleProfile:
    return RuleProfile(
        sid=sid,
        evidence_fingerprint=fingerprint,
        logic_fingerprint=logic_fingerprint or fingerprint,
        normalized_text=text or f"rule-{sid}",
        complexity=complexity,
        direction=direction,
        detection_scope=detection_scope,
        pcre_count=pcre_count,
    )


def _sample(name: str, expected: str, *matched_sids: int) -> dict[str, object]:
    return {
        "name": name,
        "expected": expected,
        "matched_sids": list(matched_sids),
    }


def test_coverage_graph_proves_duplicates_dominance_and_recommended_set() -> None:
    profiles = [
        _profile(100, "endpoint+exploit", complexity=2),
        _profile(101, "method+endpoint+exploit", complexity=3),
        _profile(102, "broad-exploit", complexity=1),
        _profile(103, "response-evidence", complexity=4),
        _profile(104, "response-evidence", complexity=7),
    ]
    samples = [
        _sample("positive-1", "alert", 100, 101),
        _sample("positive-2", "alert", 100, 101),
        _sample("positive-3", "alert", 102, 103, 104),
        _sample("negative-1", "no_alert", 102),
        _sample("negative-2", "no_alert"),
    ]

    analysis = analyze_coverage(profiles, samples)

    assert analysis.recommended_sids == (100, 103)
    assert analysis.covered_positive_samples == (
        "positive-1",
        "positive-2",
        "positive-3",
    )
    assert analysis.false_positive_samples == ()
    assert analysis.optimization_method == "exact"

    relations = {
        (item.kind, item.source_sid, item.target_sid)
        for item in analysis.relations
    }
    assert ("dominates", 100, 101) in relations
    assert ("dominates", 103, 102) in relations
    assert ("logic_duplicate", 103, 104) in relations

    recommendations = {item.sid: item for item in analysis.recommendations}
    assert recommendations[101].reason_code == "COVERAGE_DUPLICATE"
    assert recommendations[101].replaced_by_sid == 100
    assert recommendations[102].reason_code == "SUBSUMED"
    assert recommendations[102].replaced_by_sid == 103
    assert recommendations[104].reason_code == "LOGIC_DUPLICATE"


def test_exact_optimizer_prioritizes_fp_then_rule_count_then_complexity() -> None:
    profiles = [
        _profile(200, "combined-with-fp", complexity=1),
        _profile(201, "left", complexity=3),
        _profile(202, "right", complexity=3),
        _profile(203, "left-expensive", complexity=8),
    ]
    samples = [
        _sample("positive-left", "alert", 200, 201, 203),
        _sample("positive-right", "alert", 200, 202),
        _sample("negative-near-miss", "no_alert", 200),
    ]

    analysis = analyze_coverage(profiles, samples)

    assert analysis.recommended_sids == (201, 202)
    assert analysis.false_positive_samples == ()
    assert analysis.uncovered_positive_samples == ()


def test_large_candidate_set_uses_deterministic_greedy_cover() -> None:
    profiles = [
        _profile(300 + index, f"feature-{index}", complexity=index + 1)
        for index in range(4)
    ]
    samples = [
        _sample("positive-1", "alert", 300, 301),
        _sample("positive-2", "alert", 300, 302),
        _sample("positive-3", "alert", 303),
        _sample("negative-1", "no_alert", 300),
    ]

    analysis = analyze_coverage(profiles, samples, exact_limit=2)

    assert analysis.optimization_method == "greedy"
    assert analysis.recommended_sids == (300, 303)


def test_coverage_graph_rejects_ambiguous_inputs() -> None:
    profile = _profile(400, "feature", complexity=1)

    with pytest.raises(ValueError, match="SID 不能重复"):
        analyze_coverage([profile, profile], [])
    with pytest.raises(ValueError, match="样本名称重复"):
        analyze_coverage(
            [profile],
            [
                _sample("same", "alert", 400),
                _sample("same", "no_alert"),
            ],
        )
    with pytest.raises(ValueError, match="expected"):
        analyze_coverage(
            [profile],
            [_sample("invalid", "maybe", 400)],
        )


def test_coverage_graph_rejects_empty_or_mismatched_coverage_evidence() -> None:
    profiles = [
        _profile(420, "left", complexity=1),
        _profile(421, "right", complexity=1),
    ]

    with pytest.raises(ValueError, match="sample_results 不能为空"):
        analyze_coverage(profiles, [])
    with pytest.raises(ValueError, match="expected_any_sids 与当前规则 SID 不匹配"):
        analyze_coverage(
            profiles,
            [
                {
                    "name": "wrong-report",
                    "expected": "alert",
                    "expected_any_sids": [999],
                    "matched_sids": [999],
                }
            ],
        )
    with pytest.raises(ValueError, match="无法证明当前规则 SID 已被完整评估"):
        analyze_coverage(
            profiles,
            [_sample("legacy-partial", "alert", 420)],
        )


def test_coverage_graph_allows_proven_all_zero_coverage() -> None:
    profiles = [
        _profile(430, "left", complexity=1),
        _profile(431, "right", complexity=1),
    ]
    samples = [
        {
            "name": "positive-zero-hit",
            "expected": "alert",
            "expected_any_sids": [430, 431],
            "matched_sids": [],
        },
        {
            "name": "negative-zero-hit",
            "expected": "no_alert",
            "expected_any_sids": [430, 431],
            "matched_sids": [],
        },
    ]

    analysis = analyze_coverage(profiles, samples)

    assert analysis.recommended_sids == ()
    assert analysis.covered_positive_samples == ()
    assert analysis.uncovered_positive_samples == ("positive-zero-hit",)


def test_explicit_evaluated_sids_allows_legacy_zero_hit_samples() -> None:
    profiles = [_profile(440, "feature", complexity=1)]

    analysis = analyze_coverage(
        profiles,
        [_sample("positive-zero-hit", "alert")],
        evaluated_sids=[440],
    )

    assert analysis.recommended_sids == ()
    assert analysis.uncovered_positive_samples == ("positive-zero-hit",)


def test_text_duplicate_label_never_overrides_observed_coverage() -> None:
    profiles = [
        _profile(410, "same", complexity=1, text="same-rule"),
        _profile(411, "same", complexity=2, text="same-rule"),
    ]
    samples = [
        _sample("positive-1", "alert", 410, 411),
        _sample("positive-2", "alert", 411),
    ]

    analysis = analyze_coverage(profiles, samples)

    assert analysis.recommended_sids == (411,)
    assert analysis.uncovered_positive_samples == ()


def test_cross_direction_rules_never_replace_each_other() -> None:
    profiles = [
        _profile(
            450,
            "same-evidence",
            logic_fingerprint="same-logic",
            text="same-text",
            complexity=1,
            direction="request",
        ),
        _profile(
            451,
            "same-evidence",
            logic_fingerprint="same-logic",
            text="same-text",
            complexity=2,
            direction="response",
        ),
    ]
    samples = [
        _sample("positive", "alert", 450, 451),
        _sample("negative", "no_alert"),
    ]

    analysis = analyze_coverage(profiles, samples)

    assert analysis.recommended_sids == (450, 451)
    assert analysis.relations == ()
    assert all(item.keep for item in analysis.recommendations)
    assert {node.sid: node.direction for node in analysis.nodes} == {
        450: "request",
        451: "response",
    }


def test_rule_ir_direction_partitions_coverage_optimization() -> None:
    rules = """
alert http any any -> any any (flow:to_server; http.uri; content:"../"; sid:460;)
alert http any any -> any any (flow:to_client; file_data; content:"../"; sid:461;)
"""
    samples = [
        _sample("positive", "alert", 460, 461),
        _sample("negative", "no_alert"),
    ]

    analysis = analyze_rule_coverage(rules, samples)

    assert analysis.recommended_sids == (460, 461)
    assert {node.sid: node.direction for node in analysis.nodes} == {
        460: "request",
        461: "response",
    }
    assert not any(
        {relation.source_sid, relation.target_sid} == {460, 461}
        for relation in analysis.relations
    )


def test_different_detection_scopes_never_replace_each_other() -> None:
    profiles = [
        _profile(
            470,
            "same-evidence",
            complexity=1,
            detection_scope="case_specific",
        ),
        _profile(
            471,
            "same-evidence",
            complexity=2,
            detection_scope="exploit_family",
        ),
    ]
    samples = [
        _sample("positive", "alert", 470, 471),
        _sample("negative", "no_alert"),
    ]

    analysis = analyze_coverage(profiles, samples)

    assert analysis.recommended_sids == (470, 471)
    assert analysis.relations == ()
    assert {node.sid: node.detection_scope for node in analysis.nodes} == {
        470: "case_specific",
        471: "exploit_family",
    }


def test_coverage_ignores_hits_outside_sample_sid_contract() -> None:
    profiles = [
        _profile(480, "request", complexity=1, direction="request"),
        _profile(
            481,
            "response",
            complexity=1,
            direction="response",
            detection_scope="success_indicator",
        ),
    ]
    samples = [
        {
            "name": "positive-original",
            "expected": "alert",
            "expected_any_sids": [480, 481],
            "matched_sids": [480, 481],
        },
        {
            "name": "negative-response-decoy",
            "expected": "no_alert",
            "expected_any_sids": [481],
            "matched_sids": [480],
        },
    ]

    analysis = analyze_coverage(profiles, samples)
    nodes = {node.sid: node for node in analysis.nodes}

    assert nodes[480].negative_hits == ()
    assert nodes[481].negative_hits == ()


def test_rule_ir_adapter_ignores_management_fields_but_keeps_detection_logic() -> None:
    rules = """
alert http any any -> any any (flow:established,to_server; http.method; content:"GET"; http.uri; content:"/download"; http.uri; content:"../"; msg:"A"; sid:500; rev:1;)
alert http any any -> any any (flow:established,to_server; http.method; content:"GET"; http.uri; content:"/download"; http.uri; content:"../"; msg:"B"; sid:501; rev:9;)
"""
    samples = [
        _sample("positive", "alert", 500, 501),
        _sample("negative", "no_alert"),
    ]

    analysis = analyze_rule_coverage(rules, samples)

    assert analysis.recommended_sids == (500,)
    assert analysis.nodes[0].evidence_fingerprint.startswith("efp:v1:")
    assert any(
        relation.kind == "text_duplicate"
        and relation.source_sid == 500
        and relation.target_sid == 501
        for relation in analysis.relations
    )


def test_logic_duplicate_keeps_method_nocase_and_polarity_semantics() -> None:
    rules = r'''
alert http any any -> any any (flow:to_server; http.method; content:"GET"; http.uri; content:"/Admin"; nocase; content:!"disabled"; sid:520;)
alert http any any -> any any (flow:to_server; http.method; content:"POST"; http.uri; content:"/Admin"; content:"disabled"; sid:521;)
'''
    samples = [
        _sample("positive", "alert", 520, 521),
        _sample("negative", "no_alert"),
    ]

    analysis = analyze_rule_coverage(rules, samples)
    pair_relations = [
        relation
        for relation in analysis.relations
        if {relation.source_sid, relation.target_sid} == {520, 521}
    ]

    assert any(relation.kind == "coverage_duplicate" for relation in pair_relations)
    assert not any(relation.kind == "logic_duplicate" for relation in pair_relations)
    assert analysis.nodes[0].logic_fingerprint.startswith("lfp:v1:")
