from __future__ import annotations

import json
import re
from pathlib import Path

from main import WorkflowConfig, build_workflow
from final_judge import FinalJudgment
from traffic_cases import MutationSkip, TrafficSample, TrafficSampleList


_PLAN = json.dumps(
    {
        "candidates": [
            {
                "role": "precision",
                "detection_scope": "case_specific",
                "direction": "request",
                "protocol": "http",
                "method": "GET",
                "features": [
                    {"buffer": "http.uri.raw", "content": "/download"},
                    {"buffer": "http.uri.raw", "content": "../etc/passwd"},
                ],
                "dynamic_fields": ["Host"],
                "reason": "接口和目录遍历语义共同降低误报",
            },
            {
                "role": "robust",
                "detection_scope": "case_specific",
                "direction": "request",
                "protocol": "http",
                "method": None,
                "features": [
                    {"buffer": "http.uri.raw", "content": "/download"},
                    {"buffer": "http.uri.raw", "content": "../"}
                ],
                "dynamic_fields": ["Host"],
                "reason": "减少接口绑定以抵抗路径变化",
            },
            {
                "role": "alternative_evidence",
                "detection_scope": "success_indicator",
                "direction": "response",
                "protocol": "http",
                "method": None,
                "features": [
                    {"buffer": "file_data", "content": "[fonts]"},
                    {"buffer": "file_data", "content": "[extensions]"},
                ],
                "dynamic_fields": ["Content-Length"],
                "reason": "使用文件读取成功后的独立响应证据",
            },
        ]
    },
    ensure_ascii=False,
)


def _validation(rules: str, samples: list[TrafficSample], **_kwargs: object):
    sids = [int(value) for value in re.findall(r"\bsid:(\d+)", rules)]
    sample_results = [
        {
            "name": samples[0].name,
            "expected": "alert",
            "reason": samples[0].reason,
            "expected_any_sids": sids,
            "matched_sids": sids,
            "passed": True,
        },
        {
            "name": samples[1].name,
            "expected": "no_alert",
            "reason": samples[1].reason,
            "expected_any_sids": sids,
            "matched_sids": [],
            "passed": True,
        },
        {
            "name": "positive-response-oracle",
            "expected": "alert",
            "reason": "响应成功证据的稳定变体",
            "validates": "response_detection",
            "expected_any_sids": [sids[-1]],
            "matched_sids": [sids[-1]],
            "passed": True,
        },
        {
            "name": "negative-response-oracle",
            "expected": "no_alert",
            "reason": "与成功证据相似但不代表攻击成功",
            "validates": "response_detection",
            "expected_any_sids": [sids[-1]],
            "matched_sids": [],
            "passed": True,
        },
    ]
    return {
        "passed": True,
        "validation_level": "sample_matrix",
        "completed_stages": ["static", "syntax", "positive", "negative"],
        "failed_stage": None,
        "error_code": None,
        "retryable": False,
        "syntax_ok": True,
        "positive_match_ok": True,
        "negative_match_ok": True,
        "expected_sids": sids,
        "positive_matched_sids": sids,
        "negative_matched_sids": [],
        "errors": [],
        "warnings": [],
        "command_output": "",
        "sample_results": sample_results,
        "positive_coverage": 1.0,
        "false_positive_count": 0,
        "quality_warnings": [],
    }


def test_workflow_persists_mutation_ir_fingerprint_and_final_judgment(
    tmp_path: Path,
) -> None:
    source_pcap = tmp_path / "source.pcap"
    source_pcap.write_bytes(b"pcap-placeholder")
    request = b"GET /download?path=../../etc/passwd HTTP/1.1\r\nHost: x\r\n\r\n"
    response = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n[fonts]"
    strategy_catalog = tmp_path / "detection-strategies.json"
    strategy_catalog.write_text(
        json.dumps(
            {
                "version": 1,
                "clusters": [
                    {
                        "cluster_id": "strategy:v1:path",
                        "exploit_families": ["path_traversal"],
                        "recommended_sids": [900],
                        "buffers": ["http.uri.raw"],
                        "representation_variants": ["../"],
                        "summary": {
                            "family": "Path Traversal",
                            "core_strategy": "endpoint 与 traversal semantic",
                            "representation_variants": ["raw traversal"],
                            "do_not_bind": ["Host"],
                        },
                    }
                ],
            },
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )

    def traffic_builder(*_args: object, **_kwargs: object) -> TrafficSampleList:
        samples = [
            TrafficSample(
                name="positive-original",
                expected="alert",
                reason="原始攻击证据",
                source="original",
                pcap_path=source_pcap,
                request=request,
                response=response,
            ),
            TrafficSample(
                name="negative-near-miss",
                expected="no_alert",
                reason="只保留正常参数",
                source="derived",
                pcap_path=source_pcap,
                request=b"GET /download?path=report.pdf HTTP/1.1\r\nHost: x\r\n\r\n",
                response=response,
            ),
        ]
        return TrafficSampleList(
            samples,
            (
                MutationSkip(
                    "CONTENT_TYPE_UNSUPPORTED",
                    "application/octet-stream",
                    "二进制正文不自动改写",
                ),
            ),
        )

    extractor_calls: list[dict[str, object]] = []

    def feature_extractor(*_args: object, **kwargs: object) -> str:
        extractor_calls.append(kwargs)
        return _PLAN

    graph = build_workflow(
        model=object(),
        config=WorkflowConfig(
            max_rule_attempts=1,
            strategy_catalog=str(strategy_catalog),
        ),
        runtime_checker=lambda **_kwargs: {
            "ok": True,
            "suricata_bin": "suricata",
            "config_path": "suricata.yaml",
            "error_code": None,
            "message": None,
        },
        traffic_builder=traffic_builder,
        feature_extractor=feature_extractor,
        matrix_validator=_validation,
        candidate_judge=lambda **_kwargs: FinalJudgment(
            selected_candidate=2,
            reason="更少绑定具体 payload，同时保留 endpoint",
            overfitting_risks=("仍需扩大正常流量集",),
        ),
    )
    output_dir = tmp_path / "artifacts"
    state = graph.invoke(
        {
            "case_id": "contract-case",
            "base": "路径遍历",
            "poc": "读取 passwd",
            "http_request": request,
            "http_response": response,
            "output_dir": str(output_dir),
            "negative_pcap_paths": [],
            "attempt": 0,
            "attempts": [],
            "status": "running",
        }
    )

    assert state["status"] == "passed"
    assert (output_dir / "traffic-mutations.json").is_file()
    assert (output_dir / "generated.rule-ir.json").is_file()
    assert (output_dir / "supplemental.rules").is_file()
    assert (output_dir / "supplemental.rule-ir.json").is_file()
    assert (output_dir / "final-judgment.json").is_file()
    assert not (output_dir / "coverage-graph.json").exists()

    primary_rules = (output_dir / "generated.rules").read_text(encoding="utf-8")
    supplemental_rules = (output_dir / "supplemental.rules").read_text(
        encoding="utf-8"
    )
    assert re.findall(r"\bsid:(\d+)", primary_rules) == ["123"]
    assert re.findall(r"\bsid:(\d+)", supplemental_rules) == ["124"]
    supplemental_ir_artifact = json.loads(
        (output_dir / "supplemental.rule-ir.json").read_text(encoding="utf-8")
    )
    assert [item["sid"] for item in supplemental_ir_artifact["rules"]] == [124]

    report = json.loads(
        (output_dir / "validation-report.json").read_text(encoding="utf-8")
    )
    assert report["mutation_skips"][0]["code"] == "CONTENT_TYPE_UNSUPPORTED"
    assert report["rule_ir"]["sid"] == 123
    assert report["supplemental_rules"] == "supplemental.rules"
    assert [item["sid"] for item in report["supplemental_rule_ir"]] == [124]
    assert report["final_judgment"] == {
        "selected_candidate": 2,
        "reason": "更少绑定具体 payload，同时保留 endpoint",
        "overfitting_risks": ["仍需扩大正常流量集"],
        "source": "llm_final_judge",
    }
    assert report["strategy_context"][0]["cluster_id"] == "strategy:v1:path"
    assert extractor_calls[0]["strategy_context"][0]["cluster_id"] == (
        "strategy:v1:path"
    )

    candidates = report["attempts"][0]["candidates"]
    assert [item["role"] for item in candidates] == [
        "precision",
        "robust",
        "alternative_evidence",
    ]
    for candidate in candidates:
        assert candidate["evidence_fingerprint"]["version"] == 1
        assert candidate["evidence_fingerprint_id"].startswith("efp:v1:")
        assert "novel_evidence" in candidate
        assert candidate["expected_tradeoff"]
        assert candidate["rule_ir"]["sid"] >= 123
    selected = next(item for item in candidates if item["selected"])
    assert selected["detection_scope"] == "case_specific"
    assert selected["selection_tier"] == "primary"
    assert selected["candidate_index"] == 2
    assert selected["final_sid"] == 123
    assert "metadata:detection_scope case_specific" in selected["final_rule"]
    assert selected["delivered"] is True
    assert selected["supplemental_final_rule"] is None
    supplemental = next(
        item for item in candidates if item["selection_tier"] == "supplemental"
    )
    assert supplemental["passed"] is True
    assert supplemental["selected"] is False
    assert supplemental["delivered"] is True
    assert supplemental["final_sid"] == 124
    assert "sid:124" in supplemental["supplemental_final_rule"]
    assert supplemental["supplemental_rule_ir"]["sid"] == 124
    assert supplemental["final_rule"] is None
    assert state["supplemental_rules"] == supplemental["supplemental_final_rule"]
    assert [item["sid"] for item in state["supplemental_rule_irs"]] == [124]

    attempt_dir = output_dir / "attempts" / "001"
    assert (attempt_dir / "supplemental.rules").read_text(
        encoding="utf-8"
    ) == supplemental_rules
    archived_supplemental = json.loads(
        (attempt_dir / "candidate-03-result.json").read_text(encoding="utf-8")
    )
    assert archived_supplemental["delivered"] is True
    assert archived_supplemental["final_sid"] == 124
    archived_judgment = json.loads(
        (attempt_dir / "final-judgment.json").read_text(encoding="utf-8")
    )
    assert archived_judgment["selected_candidate"] == 2


def test_web_artifact_catalog_exposes_supplemental_download_kinds(
    tmp_path: Path,
) -> None:
    import web_app

    output_dir = tmp_path / "artifacts"
    output_dir.mkdir()
    (output_dir / "supplemental.rules").write_text(
        'alert http any any -> any any (msg:"supplement"; sid:124; rev:1;)\n',
        encoding="utf-8",
    )
    (output_dir / "supplemental.rule-ir.json").write_text(
        json.dumps({"rules": [{"sid": 124}]}),
        encoding="utf-8",
    )
    job_id = "supplemental-artifact-contract"
    job = {"job_id": job_id, "output_dir": output_dir}
    with web_app._jobs_lock:
        web_app._jobs[job_id] = job
        web_app._collect_artifacts(job)
    try:
        assert {
            "supplemental_rules",
            "supplemental_rule_ir",
        } <= job["artifact_paths"].keys()
        assert {
            item["kind"] for item in job["artifact_dtos"]
        } == {"supplemental_rules", "supplemental_rule_ir"}
        rules_response = web_app.download_artifact(job_id, "supplemental_rules")
        ir_response = web_app.download_artifact(job_id, "supplemental_rule_ir")
        assert Path(rules_response.path).name == "supplemental.rules"
        assert Path(ir_response.path).name == "supplemental.rule-ir.json"
    finally:
        with web_app._jobs_lock:
            web_app._jobs.pop(job_id, None)


def test_web_artifact_catalog_exposes_python_poc_extraction_files(
    tmp_path: Path,
) -> None:
    import web_app

    output_dir = tmp_path / "artifacts"
    output_dir.mkdir()
    expected = {
        "python_poc": "poc-source.py",
        "poc_extraction": "poc-extraction.json",
        "extracted_request": "selected-request.raw",
        "http_candidates": "http-candidates.json",
        "extraction_report": "extraction-report.json",
    }
    for filename in expected.values():
        (output_dir / filename).write_text("fixture", encoding="utf-8")

    job_id = "python-poc-artifact-contract"
    job = {"job_id": job_id, "output_dir": output_dir}
    with web_app._jobs_lock:
        web_app._jobs[job_id] = job
        web_app._collect_artifacts(job)
    try:
        assert set(job["artifact_paths"]) == set(expected)
        assert {item["kind"] for item in job["artifact_dtos"]} == set(expected)
        for kind, filename in expected.items():
            response = web_app.download_artifact(job_id, kind)
            assert Path(response.path).name == filename
    finally:
        with web_app._jobs_lock:
            web_app._jobs.pop(job_id, None)


def test_invalid_strategy_catalog_returns_structured_preflight_failure(
    tmp_path: Path,
) -> None:
    catalog = tmp_path / "invalid-strategies.json"
    catalog.write_text(
        json.dumps(
            {
                "version": 1,
                "clusters": [
                    {
                        "cluster_id": "broken",
                        "exploit_families": ["path_traversal"],
                        "recommended_sids": "not-an-array",
                        "buffers": [],
                        "representation_variants": [],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    graph = build_workflow(
        model=object(),
        config=WorkflowConfig(strategy_catalog=str(catalog)),
        runtime_checker=lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("catalog 失败时不应启动 Suricata")
        ),
    )

    state = graph.invoke(
        {
            "case_id": "invalid-catalog",
            "base": "路径遍历",
            "poc": "读取文件",
            "http_request": b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
            "http_response": b"",
            "output_dir": str(tmp_path / "artifacts"),
            "negative_pcap_paths": [],
            "attempt": 0,
            "attempts": [],
            "status": "running",
        }
    )

    assert state["status"] == "failed"
    assert state["failure_code"] == "STRATEGY_CATALOG_ERROR"
