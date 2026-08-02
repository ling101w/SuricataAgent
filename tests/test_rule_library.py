from __future__ import annotations

import json
from pathlib import Path

import pytest

from rule_library import (
    _rule_library_policy,
    analyze_rule_library,
    load_sample_results,
    load_traffic_matrix,
    write_rule_library_artifacts,
)


_RULES = """
alert http any any -> any any (flow:established,to_server; http.uri; content:"/download"; http.uri; content:"../"; sid:700; rev:1;)
alert http any any -> any any (flow:established,to_server; http.method; content:"POST"; http.uri; content:"/download"; http.uri; content:"../"; sid:701; rev:1;)
alert http any any -> any any (flow:established,to_server; http.uri; content:"../"; sid:702; rev:1;)
alert http any any -> any any (flow:established,to_server; http.uri; content:"/download"; http.uri; content:"../"; http.uri; content:"win.ini"; sid:703; rev:1;)
"""


def _samples() -> list[dict[str, object]]:
    return [
        {"name": "positive-1", "expected": "alert", "matched_sids": [700, 701, 702, 703]},
        {"name": "positive-2", "expected": "alert", "matched_sids": [700, 701, 702]},
        {"name": "negative-1", "expected": "no_alert", "matched_sids": [702]},
    ]


def test_rule_library_requires_coverage_before_recommending_deletions() -> None:
    rules, coverage, summary = analyze_rule_library(_RULES)

    assert len(rules) == 4
    assert coverage is None
    assert summary["coverage_available"] is False
    assert summary["recommended_rule_count"] is None
    assert summary["recommendation_counts"] == {}


def test_rule_library_writes_ir_graph_and_proven_recommended_rules(
    tmp_path: Path,
) -> None:
    rules, coverage, summary = analyze_rule_library(_RULES, _samples())
    assert coverage is not None

    paths = write_rule_library_artifacts(tmp_path, rules, coverage, summary)

    assert summary["recommended_sids"] == [700]
    assert summary["recommended_rule_count"] == 1
    assert summary["relation_counts"]["dominates"] >= 2
    recommended = Path(paths["recommended_rules"]).read_text(encoding="utf-8")
    assert "sid:700" in recommended
    assert "sid:701" not in recommended
    assert "sid:702" not in recommended
    assert "sid:703" not in recommended
    ir = json.loads(Path(paths["rule_ir"]).read_text(encoding="utf-8"))
    assert [rule["sid"] for rule in ir["rules"]] == [700, 701, 702, 703]


def test_load_sample_results_accepts_validation_report_shape(tmp_path: Path) -> None:
    report_path = tmp_path / "validation-report.json"
    report_path.write_text(
        json.dumps({"validation": {"sample_results": _samples()}}),
        encoding="utf-8",
    )

    assert load_sample_results(report_path) == _samples()


def test_load_sample_results_propagates_top_level_sid_contract(tmp_path: Path) -> None:
    report_path = tmp_path / "validation-report.json"
    report_path.write_text(
        json.dumps(
            {
                "validation": {
                    "expected_sids": [700, 701, 702, 703],
                    "sample_results": [
                        {
                            "name": "positive-zero-hit",
                            "expected": "alert",
                            "matched_sids": [],
                        }
                    ],
                }
            }
        ),
        encoding="utf-8",
    )

    assert load_sample_results(report_path)[0]["expected_any_sids"] == [
        700,
        701,
        702,
        703,
    ]


def test_rule_library_rejects_empty_or_foreign_sample_results(tmp_path: Path) -> None:
    empty_report = tmp_path / "empty.json"
    empty_report.write_text(json.dumps({"sample_results": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="sample_results 不能为空"):
        load_sample_results(empty_report)

    with pytest.raises(ValueError, match="expected_any_sids 与当前规则 SID 不匹配"):
        analyze_rule_library(
            _RULES,
            [
                {
                    "name": "foreign",
                    "expected": "alert",
                    "expected_any_sids": [999],
                    "matched_sids": [999],
                }
            ],
        )


def test_rule_library_policy_accepts_selected_library_size() -> None:
    rules_text = "#" * (128 * 1024 + 17)

    policy = _rule_library_policy(rules_text, rule_count=37)

    assert policy.max_rules == 37
    assert policy.max_rule_bytes == len(rules_text.encode("utf-8"))


def test_load_traffic_matrix_restores_sample_pcap_paths(tmp_path: Path) -> None:
    sample_dir = tmp_path / "samples"
    sample_dir.mkdir()
    pcap = sample_dir / "positive-original.pcap"
    pcap.write_bytes(b"pcap")
    matrix = tmp_path / "traffic-matrix.json"
    matrix.write_text(
        json.dumps(
            [
                {
                    "name": "positive-original",
                    "expected": "alert",
                    "reason": "原始攻击证据",
                    "pcap_name": pcap.name,
                }
            ]
        ),
        encoding="utf-8",
    )

    samples = load_traffic_matrix(matrix)

    assert samples == [
        {
            "name": "positive-original",
            "expected": "alert",
            "reason": "原始攻击证据",
            "pcap_path": pcap.resolve(),
        }
    ]
