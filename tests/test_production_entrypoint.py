from __future__ import annotations

from pathlib import Path

import benchmark_runner
import production
import web_app


def test_application_surfaces_share_the_production_contract() -> None:
    assert benchmark_runner.run_generation is production.run_generation
    assert benchmark_runner.WorkflowConfig is production.WorkflowConfig
    assert web_app.build_workflow is production.build_workflow
    assert web_app.PIPELINE_ID == production.PIPELINE_ID


def test_web_runtime_exposes_stable_pipeline_id(monkeypatch) -> None:
    from fastapi import Response

    monkeypatch.setattr(
        web_app,
        "check_suricata_runtime",
        lambda: {"ok": True, "error_code": None, "message": None},
    )

    result = web_app.runtime_status(Response())

    assert result["pipeline_id"] == production.PIPELINE_ID


def test_production_result_is_stamped_with_pipeline_id(
    tmp_path: Path,
    monkeypatch,
) -> None:
    captured: dict[str, object] = {}

    def fake_run_generation(**kwargs: object):
        captured.update(kwargs)
        return {"status": "failed"}

    monkeypatch.setattr(production, "_run_generation", fake_run_generation)

    result = production.run_generation(
        case_id="CVE-TEST",
        base="test vulnerability",
        poc="test poc",
        http_request="GET / HTTP/1.1\r\nHost: test\r\n\r\n",
        output_dir=tmp_path,
    )

    assert captured["case_id"] == "CVE-TEST"
    assert result["pipeline_id"] == "E-direct-repair-v1"


def test_benchmark_report_identifies_production_pipeline() -> None:
    report = benchmark_runner.aggregate_benchmark_results([])

    assert report["pipeline_id"] == production.PIPELINE_ID
