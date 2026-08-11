from __future__ import annotations

import main
import production
from suricata_agent.pipeline.direct import graph


def test_production_and_package_share_pipeline_identity() -> None:
    assert graph.PIPELINE_ID == production.PIPELINE_ID
    assert graph.WorkflowConfig is production.WorkflowConfig
    assert graph.run_generation is not None


def test_main_keeps_legacy_import_contract() -> None:
    assert main.WorkflowConfig.__module__.endswith("detection_plan_pipeline")
    assert callable(main.build_workflow)
    assert callable(main.run_generation)
    assert callable(main._candidate_validation)


def test_direct_support_modules_are_importable() -> None:
    from suricata_agent.pipeline.direct.artifacts import rule_sha256
    from suricata_agent.pipeline.direct.prompts import prompt_hashes
    from suricata_agent.pipeline.direct.state import WorkflowConfig

    assert len(rule_sha256("alert http any any -> any any ()")) == 64
    assert set(prompt_hashes()) == {"generate", "repair"}
    assert WorkflowConfig().sid_start == 123
