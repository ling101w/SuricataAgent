from __future__ import annotations

import benchmark_runner
import production
import web_app
from suricata_agent.benchmarks import runner
from suricata_agent.web import app


def test_web_facade_preserves_fastapi_and_production_contract() -> None:
    assert app.app is web_app.app
    assert web_app.build_workflow is production.build_workflow
    assert web_app.PIPELINE_ID == production.PIPELINE_ID


def test_benchmark_facade_preserves_production_contract() -> None:
    assert runner.run_generation is production.run_generation
    assert benchmark_runner.run_generation is production.run_generation
    assert benchmark_runner.WorkflowConfig is production.WorkflowConfig
