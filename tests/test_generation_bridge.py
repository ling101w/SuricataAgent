from __future__ import annotations

from pathlib import Path

import generation_bridge
from suricata_agent.integrations import generation_bridge as implementation


def _payload() -> dict[str, object]:
    return {
        "contract_version": 1,
        "case_id": "CVE-TEST",
        "base": "test vulnerability",
        "poc": "GET /vulnerable?id=attack HTTP/1.1",
        "input_mode": "http",
        "http_request": "GET /vulnerable?id=attack HTTP/1.1\r\nHost: example.invalid\r\n\r\n",
        "sid": 1_000_001,
        "max_attempts": 2,
    }


def _runner_state(output_dir: Path) -> dict[str, object]:
    rules_path = output_dir / "generated.rules"
    pcap_path = output_dir / "attack.pcap"
    report_path = output_dir / "validation.json"
    rules_path.write_text(
        'alert http any any -> any any (msg:"test"; sid:1000001; rev:1;)\n',
        encoding="utf-8",
    )
    pcap_path.write_bytes(b"pcap")
    report_path.write_text("{}\n", encoding="utf-8")
    return {
        "status": "passed",
        "rules": rules_path.read_text(encoding="utf-8"),
        "rules_path": rules_path,
        "pcap_path": pcap_path,
        "report_path": report_path,
        "sample_matrix": [
            {"expected": "alert"},
            {"expected": "no_alert"},
        ],
        "validation_result": {
            "passed": True,
            "positive_match_ok": True,
            "negative_match_ok": True,
            "positive_coverage": 1.0,
            "false_positive_count": 0,
        },
    }


def test_root_bridge_is_a_backward_compatible_facade() -> None:
    assert generation_bridge.run_bridge_request is implementation.run_bridge_request
    assert generation_bridge.CONTRACT_VERSION == implementation.CONTRACT_VERSION == 1


def test_bridge_exports_verified_rule_and_artifact_hashes(tmp_path: Path) -> None:
    def runner(*, output_dir: Path, **_kwargs: object) -> dict[str, object]:
        return _runner_state(Path(output_dir))

    manifest = implementation.run_bridge_request(_payload(), tmp_path, runner=runner)

    assert manifest["status"] == "passed"
    assert manifest["validation"]["positive_sample_count"] == 1
    assert manifest["validation"]["negative_sample_count"] == 1
    assert manifest["rule"]["text"].startswith("alert http")
    assert len(manifest["rule"]["sha256"]) == 64
    assert len(manifest["traffic"]["primary_pcap_sha256"]) == 64


def test_bridge_rejects_engine_pass_without_negative_sample(tmp_path: Path) -> None:
    def runner(*, output_dir: Path, **_kwargs: object) -> dict[str, object]:
        state = _runner_state(Path(output_dir))
        state["sample_matrix"] = [{"expected": "alert"}]
        return state

    manifest = implementation.run_bridge_request(_payload(), tmp_path, runner=runner)

    assert manifest["status"] == "failed"
    assert manifest["failure_code"] == "BRIDGE_NEGATIVE_SAMPLE_REQUIRED"
    assert manifest["rule"]["text"] == ""
    assert manifest["rule"]["path"] == ""
