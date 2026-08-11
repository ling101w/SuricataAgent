from __future__ import annotations

import generate_tools
import repair_constraints
import rule_ir
import rule_knowledge
import ruleops
import validate_rules

from suricata_agent.domain.rules import ir, knowledge, repair
from suricata_agent.services import llm, ruleops as ruleops_service, suricata


def test_rule_domain_modules_keep_root_identity() -> None:
    assert rule_ir.RuleIR is ir.RuleIR
    assert rule_knowledge.DetectionScope is knowledge.DetectionScope
    assert repair_constraints.RepairConstraints is repair.RepairConstraints


def test_service_modules_keep_root_identity() -> None:
    assert generate_tools.create_chat_model is llm.create_chat_model
    assert validate_rules.RulePolicy is suricata.RulePolicy
    assert ruleops.RuleOpsStore is ruleops_service.RuleOpsStore


def test_private_suricata_helper_remains_importable() -> None:
    from validate_rules import _run_suricata_command

    assert callable(_run_suricata_command)
