from __future__ import annotations

from pathlib import Path

import pytest

from rule_ir import parse_suricata_rule, rule_ir_to_dict
from ruleops import RuleOpsStore


RULE = (
    'alert http any any -> any any (flow:established,to_server; '
    'http.uri; content:"/download"; http.uri; content:"../"; sid:123; rev:1;)'
)


def _validation() -> dict[str, object]:
    return {
        "passed": True,
        "positive_coverage": 1.0,
        "false_positive_count": 0,
        "sample_results": [
            {
                "name": "positive-original",
                "expected": "alert",
                "matched_sids": [123],
                "passed": True,
            }
        ],
    }


def test_ruleops_deduplicates_verified_rules_and_tracks_observations(
    tmp_path: Path,
) -> None:
    store = RuleOpsStore(tmp_path / "rule-kb.json")
    ir = rule_ir_to_dict(parse_suricata_rule(RULE))
    first = store.ingest(
        case_id="CVE-TEST-1",
        rule=RULE,
        rule_ir=ir,
        validation=_validation(),
        sample_matrix=[],
        artifact_dir=tmp_path / "run-1",
    )
    second = store.ingest(
        case_id="CVE-TEST-1",
        rule=RULE,
        rule_ir=ir,
        validation=_validation(),
        sample_matrix=[],
        artifact_dir=tmp_path / "run-2",
    )

    overview = store.overview()
    assert first["action"] == "created"
    assert second["action"] == "deduplicated"
    assert second["duplicate_kind"] == "text"
    assert overview["stats"] == {
        "rules": 1,
        "cases": 1,
        "verified": 1,
        "duplicate_observations": 1,
        "coverage_snapshots": 0,
    }
    assert overview["records"][0]["observation_count"] == 1
    assert store.get_record(first["record"]["record_id"])["rule"] == RULE


def test_ruleops_searches_case_rule_and_evidence(tmp_path: Path) -> None:
    store = RuleOpsStore(tmp_path / "rule-kb.json")
    result = store.ingest(
        case_id="CVE-TEST-TRAVERSAL",
        rule=RULE,
        rule_ir=rule_ir_to_dict(parse_suricata_rule(RULE)),
        validation=_validation(),
        sample_matrix=[],
        artifact_dir=tmp_path / "run",
    )

    assert store.overview("TRAVERSAL")["records"][0]["record_id"] == result["record"]["record_id"]
    assert store.overview("/download")["stats"]["rules"] == 1
    assert store.overview("does-not-exist")["records"] == []


def test_ruleops_rejects_unverified_rules(tmp_path: Path) -> None:
    store = RuleOpsStore(tmp_path / "rule-kb.json")

    with pytest.raises(ValueError, match="最终 Verify"):
        store.ingest(
            case_id="CVE-TEST-FAILED",
            rule=RULE,
            rule_ir=rule_ir_to_dict(parse_suricata_rule(RULE)),
            validation={"passed": False},
            sample_matrix=[],
            artifact_dir=tmp_path / "failed-run",
        )


def test_cross_case_duplicate_remains_a_coverage_member(tmp_path: Path) -> None:
    store = RuleOpsStore(tmp_path / "rule-kb.json")
    ir = rule_ir_to_dict(parse_suricata_rule(RULE))
    store.ingest(
        case_id="CVE-TEST-A",
        rule=RULE,
        rule_ir=ir,
        validation=_validation(),
        sample_matrix=[],
        artifact_dir=tmp_path / "run-a",
    )
    duplicate = store.ingest(
        case_id="CVE-TEST-B",
        rule=RULE,
        rule_ir=ir,
        validation=_validation(),
        sample_matrix=[],
        artifact_dir=tmp_path / "run-b",
    )

    def validate(rules: str, samples: object, **_: object) -> dict[str, object]:
        assert "sid:8000000;" in rules
        assert samples
        return {
            "passed": True,
            "syntax_ok": True,
            "positive_coverage": 1.0,
            "false_positive_count": 0,
            "sample_results": [
                {
                    "name": "positive-original",
                    "expected": "alert",
                    "matched_sids": [8_000_000],
                    "passed": True,
                }
            ],
        }

    coverage = store.rebuild_case_coverage(
        "CVE-TEST-B",
        [object()],
        matrix_validator=validate,
    )
    overview = store.overview()

    assert duplicate["action"] == "deduplicated"
    assert overview["stats"]["cases"] == 2
    assert overview["records"][0]["case_ids"] == ["CVE-TEST-A", "CVE-TEST-B"]
    assert store.overview("CVE-TEST-B")["records"]
    assert coverage["case_id"] == "CVE-TEST-B"
    assert coverage["rule_count"] == 1
