from __future__ import annotations

import coverage_graph
import detection_strategy
import evidence_fingerprint

from suricata_agent.domain.rules import coverage, evidence, strategy


def test_rule_analysis_modules_keep_root_identity() -> None:
    assert coverage_graph.CoverageAnalysis is coverage.CoverageAnalysis
    assert detection_strategy.StrategyCluster is strategy.StrategyCluster
    assert evidence_fingerprint.evidence_fingerprint is evidence.evidence_fingerprint
