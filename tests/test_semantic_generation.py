from __future__ import annotations

import json

import pytest

from semantic_generation import (
    RepairDiagnosis,
    SemanticOutputError,
    analyze_detection_intent,
    generate_rule_from_intent,
    parse_detection_intent,
    parse_repair_diagnosis,
)

from benchmarks import benchmark as benchmark_v0


def _intent_payload() -> dict[str, object]:
    return {
        "vulnerability_identity": ["GET /viewPDF", "pdfUrl parameter"],
        "exploit_primitive": "pdfUrl accepts a local file URI",
        "stable_context": ["viewPDF endpoint", "pdfUrl parameter", "file URI scheme"],
        "sample_specific": ["/etc/passwd", "Host header"],
        "expected_variations": ["different local paths", "URL encoding"],
        "false_positive_risks": ["file URI on an unrelated endpoint"],
    }


def test_detection_intent_is_semantic_and_strictly_typed() -> None:
    intent = parse_detection_intent(json.dumps(_intent_payload()))

    assert intent.exploit_primitive == "pdfUrl accepts a local file URI"
    assert "/etc/passwd" in intent.sample_specific
    assert "URL encoding" in intent.expected_variations


def test_detection_intent_rejects_compiler_fields() -> None:
    payload = _intent_payload()
    payload["features"] = [{"buffer": "http.uri", "content": "file://"}]

    with pytest.raises(SemanticOutputError, match="unknown fields: features"):
        parse_detection_intent(json.dumps(payload))


def test_detection_intent_accepts_a_fenced_json_response() -> None:
    payload = "```json\n" + json.dumps(_intent_payload()) + "\n```"
    assert parse_detection_intent(payload).vulnerability_identity[0] == "GET /viewPDF"


def test_repair_diagnosis_requires_preserved_constraints() -> None:
    diagnosis = parse_repair_diagnosis(
        json.dumps(
            {
                "failure_cause": "representation overfitting",
                "which_constraint_is_too_narrow": "literal target file",
                "semantic_invariant_to_preserve": "local file URI in pdfUrl",
                "constraints_that_must_not_be_removed": [
                    "viewPDF endpoint",
                    "pdfUrl parameter",
                ],
                "permitted_change": "generalize only the target path",
            }
        )
    )
    assert diagnosis.which_constraint_is_too_narrow == "literal target file"
    assert diagnosis.constraints_that_must_not_be_removed == (
        "viewPDF endpoint",
        "pdfUrl parameter",
    )


def test_intent_and_rule_generation_use_two_separate_model_calls() -> None:
    rule = (
        'alert http any any -> any any (msg:"test"; flow:established,to_server; '
        'http.uri; content:"/viewPDF"; sid:9000000; rev:1;)'
    )

    class FakeModel:
        def __init__(self) -> None:
            self.responses = iter((json.dumps(_intent_payload()), rule))
            self.messages: list[list[object]] = []

        def invoke(self, messages):
            self.messages.append(messages)
            return next(self.responses)

    model = FakeModel()
    intent, _ = analyze_detection_intent("evidence", model=model)
    generated, _ = generate_rule_from_intent(
        "evidence", intent, model=model, sid=9_000_000
    )

    assert generated == rule
    assert len(model.messages) == 2
    assert "Suricata" not in model.messages[0][-1].content
    assert "detection_intent" in model.messages[1][-1].content


def test_benchmark_f_uses_two_calls_and_persists_intent(tmp_path) -> None:
    rule = (
        'alert http any any -> any any (msg:"test"; flow:established,to_server; '
        'http.uri; content:"/viewPDF"; sid:9000000; rev:1;)'
    )

    class FakeModel:
        def __init__(self) -> None:
            self.responses = iter((json.dumps(_intent_payload()), rule))
            self.messages: list[list[object]] = []

        def invoke(self, messages):
            self.messages.append(messages)
            return next(self.responses)

    model = FakeModel()
    input_data = benchmark_v0.ModelInput(
        case_id="case-f",
        family="file_read",
        description="A local file read vulnerability.",
        poc="Read /etc/passwd through pdfUrl.",
        poc_http="GET /viewPDF?pdfUrl=file:///etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        response_http="HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )

    generated, metadata = benchmark_v0.generate_semantic_intent(
        input_data,
        model=model,
        sid=9_000_000,
        artifact_dir=tmp_path,
    )

    assert generated == rule
    assert metadata["model_calls"] == 2
    assert len(model.messages) == 2
    assert json.loads((tmp_path / "detection-intent.json").read_text("utf-8")) == (
        _intent_payload()
    )


def _visible_validation(*, original: bool, variant: bool, negative: bool) -> dict:
    return {
        "syntax_ok": True,
        "sample_results": [
            {"name": "original", "passed": original},
            {"name": "positive-01", "passed": variant},
            {"name": "negative-01", "passed": negative},
        ],
    }


def test_benchmark_g_diagnoses_before_repair_hides_holdout_and_keeps_better_rule(
    tmp_path, monkeypatch
) -> None:
    initial_rule = (
        'alert http any any -> any any (msg:"initial"; flow:established,to_server; '
        'http.uri; content:"/viewPDF"; sid:9000000; rev:1;)'
    )
    regressed_rule = initial_rule.replace('msg:"initial"', 'msg:"regressed"')
    source_dir = tmp_path / "semantic-source"
    source_dir.mkdir()
    (source_dir / "generated.rules").write_text(initial_rule + "\n", encoding="utf-8")
    (source_dir / "result.json").write_text(
        json.dumps(
            {
                "system": "semantic_intent",
                "model_calls": 2,
                "latency_ms": 100,
                "validation": None,
            }
        ),
        encoding="utf-8",
    )
    (source_dir / "detection-intent.json").write_text(
        json.dumps(_intent_payload()), encoding="utf-8"
    )

    validations = iter(
        (
            _visible_validation(original=True, variant=True, negative=False),
            _visible_validation(original=False, variant=False, negative=True),
        )
    )
    monkeypatch.setattr(
        benchmark_v0,
        "_validate_case_samples",
        lambda *args, **kwargs: next(validations),
    )
    visible_feedback = {
        "syntax_ok": True,
        "samples": [
            {"name": "original", "passed": True},
            {"name": "positive-01", "passed": True},
            {"name": "negative-01", "passed": False},
        ],
    }
    monkeypatch.setattr(
        benchmark_v0,
        "_repair_feedback",
        lambda *args, **kwargs: visible_feedback,
    )

    diagnosis = {
        "failure_cause": "false positive",
        "which_constraint_is_too_narrow": None,
        "semantic_invariant_to_preserve": "local file URI in pdfUrl",
        "constraints_that_must_not_be_removed": ["viewPDF endpoint"],
        "permitted_change": "add only the missing parameter anchor",
    }

    class FakeModel:
        def __init__(self) -> None:
            self.responses = iter((json.dumps(diagnosis), regressed_rule))
            self.messages: list[list[object]] = []

        def invoke(self, messages):
            self.messages.append(messages)
            return next(self.responses)

    model = FakeModel()
    input_data = benchmark_v0.ModelInput(
        case_id="case-g",
        family="file_read",
        description="A local file read vulnerability.",
        poc="Read /etc/passwd through pdfUrl.",
        poc_http="GET /viewPDF?pdfUrl=file:///etc/passwd HTTP/1.1\r\nHost: target\r\n\r\n",
        response_http="HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    )
    artifact_dir = tmp_path / "g-result"
    artifact_dir.mkdir()

    generated, metadata = benchmark_v0.generate_semantic_intent_repair(
        input_data,
        tmp_path,
        model=model,
        artifact_dir=artifact_dir,
        source_dir=source_dir,
        max_attempts=2,
        suricata_bin=None,
        suricata_config=None,
    )

    assert generated == initial_rule
    assert metadata["selected_attempt"] == 0
    assert metadata["diagnosis_calls"] == 1
    assert metadata["repair_attempts"] == 1
    assert len(model.messages) == 2
    assert "diagnose" in model.messages[0][0].content
    assert "applying an approved" in model.messages[1][0].content
    all_prompt_text = "\n".join(
        message.content for call in model.messages for message in call
    )
    assert "positive-02" not in all_prompt_text
    assert "negative-02" not in all_prompt_text
