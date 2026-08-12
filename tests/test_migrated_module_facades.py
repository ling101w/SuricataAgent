from __future__ import annotations

import diagnosis
import final_judge
import generate_pcap
import generate_rules
import pcap_tcp_analysis
import poc_http_extractor
import rule_compiler
import traffic_cases
from suricata_agent.domain.rules import compiler, diagnosis as diagnosis_impl
from suricata_agent.integrations import poc_http
from suricata_agent.legacy import final_judge as final_judge_impl
from suricata_agent.legacy import generate_rules as generate_rules_impl
from suricata_agent.traffic import analysis, cases, pcap


def test_rule_module_facades_preserve_object_identity() -> None:
    assert rule_compiler.DetectionPlan is compiler.DetectionPlan
    assert diagnosis.diagnose_candidate is diagnosis_impl.diagnose_candidate


def test_traffic_module_facades_preserve_object_identity() -> None:
    assert generate_pcap.PcapConfig is pcap.PcapConfig
    assert pcap_tcp_analysis.Endpoint is analysis.Endpoint
    assert traffic_cases.TrafficSample is cases.TrafficSample


def test_integration_facade_preserves_object_identity() -> None:
    assert poc_http_extractor.PocHttpExtractionError is poc_http.PocHttpExtractionError
    assert poc_http_extractor.extract_http_request is poc_http.extract_http_request


def test_legacy_module_facades_preserve_object_identity() -> None:
    assert generate_rules.extract_detection_features is generate_rules_impl.extract_detection_features
    assert final_judge.FinalJudgment is final_judge_impl.FinalJudgment
