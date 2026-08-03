from __future__ import annotations

import json
from pathlib import Path

from benchmarks.benchmark import _extract_http_request, load_model_input
from benchmarks.build_hidden_v1_cases import PROVENANCE, build, definitions
from benchmarks.build_v0_cases import render_request
from benchmarks.freeze_hidden_test_results import _write_deltas
from traffic_cases import parse_http_request


def test_hidden_v1_definitions_are_disjoint_and_well_formed() -> None:
    cases = definitions()
    dev_manifest = json.loads(
        Path("benchmarks/v0-manifest.json").read_text(encoding="utf-8")
    )
    dev_ids = {item["case_id"] for item in dev_manifest["cases"]}

    assert len(cases) == 30
    assert len({case.case_id for case in cases}) == 30
    assert not dev_ids & {case.case_id for case in cases}
    assert set(PROVENANCE) == {case.case_id for case in cases}
    for case in cases:
        assert case.original.name == "original"
        assert tuple(item.name for item in case.positives) == (
            "positive-01",
            "positive-02",
        )
        assert tuple(item.name for item in case.negatives) == (
            "negative-01",
            "negative-02",
        )
        rendered = [
            render_request(item.request)
            for item in (case.original, *case.positives, *case.negatives)
        ]
        assert len(set(rendered)) == 5
        for request_text in rendered:
            parse_http_request(request_text)


def test_hidden_v1_build_separates_model_input_and_oracle(tmp_path) -> None:
    output = tmp_path / "hidden-test-v1"
    manifest = build(output)
    runner = json.loads((output / "manifest.runner.json").read_text("utf-8"))
    public = json.loads((output / "manifest.public.json").read_text("utf-8"))
    sealed = json.loads(
        (output / "sealed-assets-manifest.json").read_text("utf-8")
    )

    assert manifest["split"] == "test"
    assert public["case_count"] == runner["case_count"] == 30
    assert public["pcap_count"] == runner["pcap_count"] == 150
    assert runner["split"] == "dev"
    assert public["cases"] == runner["cases"]
    assert len(sealed["assets"]) == 30 * 7

    for item in public["cases"]:
        case_root = output / item["path"]
        model_input = load_model_input(case_root)
        oracle = json.loads((case_root / "oracle.json").read_text("utf-8"))
        assert model_input.case_id == item["case_id"]
        assert "positive-02" not in model_input.poc_http
        assert "negative-02" not in model_input.poc_http
        assert [entry["name"] for entry in oracle["positive"]] == [
            "original",
            "positive-01",
            "positive-02",
        ]
        assert [entry["name"] for entry in oracle["negative"]] == [
            "negative-01",
            "negative-02",
        ]
        for entry in (*oracle["positive"], *oracle["negative"]):
            request_text = _extract_http_request(case_root / entry["pcap"])
            parse_http_request(request_text)


def test_hidden_decision_rule_uses_preregistered_recall_and_fp_thresholds(
    tmp_path,
) -> None:
    def system(name: str, recall: float, fp: float) -> dict:
        return {
            "system": name,
            "heldout_variant_recall": recall,
            "heldout_false_positive_rate": fp,
            "verified_rule_rate": 0.5,
            "syntax_pass_rate": 1.0,
            "original_detection_rate": 0.8,
            "variant_recall": 0.7,
            "false_positive_rate": fp,
        }

    passing = {
        "systems": [
            system("direct_llm", 0.5, 0.1),
            system("direct_repair", 0.55, 0.12),
            system("semantic_intent_repair", 0.6, 0.15),
        ]
    }
    result = _write_deltas(tmp_path / "passing.json", passing)
    assert result["architecture_confirmation_threshold_passed"] is True

    passing["systems"][-1] = system("semantic_intent_repair", 0.6, 0.151)
    result = _write_deltas(tmp_path / "failing.json", passing)
    assert result["architecture_confirmation_threshold_passed"] is False
