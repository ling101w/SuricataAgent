from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace

import pytest

from evidence_fingerprint import (
    candidate_evidence_set,
    evidence_fingerprint,
    evidence_fingerprint_id,
    novel_evidence,
)
from generate_rules import SYSTEM_PROMPT, extract_detection_features
from main import (
    _candidate_reference_metrics,
    _candidate_validation,
    _deterministic_primary_fallback,
    _remap_validation_sid,
)
from rule_knowledge import (
    CANDIDATE_ROLES,
    FORBIDDEN_MODEL_FEATURE_BUFFERS,
    MODEL_FEATURE_BUFFERS,
    REQUEST_BUFFERS,
    MAX_CANDIDATES,
    MIN_CANDIDATES,
    RESPONSE_BUFFERS,
)
from rule_compiler import (
    DetectionCandidate,
    DetectionFeature,
    DetectionSchemaError,
    compile_candidate,
    compile_candidates,
    lint_candidate,
    parse_detection_data,
)
from validate_rules import _sample_expected_sids


def _candidate_data(role: str) -> dict[str, object]:
    """返回一份最小且合法的模型候选数据。"""
    if role == "alternative_evidence":
        direction = "response"
        method = None
        features = [
            {"buffer": "file_data", "content": "[fonts]"},
            {"buffer": "file_data", "content": "[extensions]"},
        ]
    elif role == "robust":
        direction = "request"
        method = None
        features = [
            {"buffer": "http.uri.raw", "content": "/DocumentByPath"},
            {"buffer": "http.uri.raw", "content": "../etc/passwd"},
        ]
    else:
        direction = "request"
        method = "GET"
        features = [
            {
                "buffer": "http.uri.raw",
                "content": "/DocumentByPath",
            },
            {
                "buffer": "http.uri.raw",
                "content": "path=..\\Windows\\win.ini",
                "nocase": True,
            }
        ]
    return {
        "role": role,
        "detection_scope": (
            "success_indicator"
            if role == "alternative_evidence" and direction == "response"
            else "case_specific"
        ),
        "direction": direction,
        "protocol": "http",
        "method": method,
        "features": features,
        "dynamic_fields": ["Host"],
        "reason": "目录遍历值能够区分攻击请求",
    }


@pytest.mark.parametrize(
    "payload",
    [
        pytest.param(_candidate_data("precision"), id="裸候选"),
        pytest.param(
            {"candidates": [_candidate_data("precision") for _ in range(4)]},
            id="四个候选",
        ),
    ],
)
def test_detection_plan_rejects_invalid_top_level_or_candidate_count(
    payload: object,
) -> None:
    """顶层必须是计划对象，且候选数不能超过上限。"""
    with pytest.raises(DetectionSchemaError):
        parse_detection_data(payload)


def test_detection_plan_accepts_one_to_three_unique_strategies() -> None:
    """证据有限时允许一个候选，多策略时 role 可按实际价值排序。"""
    single = parse_detection_data({"candidates": [_candidate_data("precision")]})
    plan = parse_detection_data(
        {
            "candidates": [
                _candidate_data("robust"),
                _candidate_data("precision"),
                _candidate_data("alternative_evidence"),
            ]
        }
    )

    assert len(single.candidates) == 1
    assert tuple(candidate.role for candidate in plan.candidates) == (
        "robust",
        "precision",
        "alternative_evidence",
    )


@pytest.mark.parametrize("weak_value", ["error", "OK", "success"])
def test_response_candidate_rejects_generic_status_text(weak_value: str) -> None:
    """单个通用响应词不能冒充攻击成功证据。"""
    values = [_candidate_data(role) for role in CANDIDATE_ROLES]
    values[2]["features"] = [{"buffer": "file_data", "content": weak_value}]

    with pytest.raises(DetectionSchemaError, match="通用状态文本"):
        parse_detection_data({"candidates": values})


def test_detection_plan_rejects_duplicate_roles() -> None:
    """策略标签可换序，但不能用重复 role 凑候选数。"""
    with pytest.raises(DetectionSchemaError, match="role 必须唯一"):
        parse_detection_data(
            {
                "candidates": [
                    _candidate_data("precision"),
                    _candidate_data("precision"),
                ]
            }
        )


def test_batch_compiler_accepts_subsets_and_rejects_empty_plan() -> None:
    """编译器按实际策略顺序工作，同时保留候选数量下限。"""
    plan = parse_detection_data(
        {"candidates": [_candidate_data(role) for role in CANDIDATE_ROLES]}
    )

    assert len(compile_candidates(plan.candidates[:2]).candidates) == 2
    assert len(
        compile_candidates(
            (plan.candidates[1], plan.candidates[0], plan.candidates[2])
        ).candidates
    ) == 3
    with pytest.raises(ValueError, match="候选数量必须在"):
        compile_candidates(())


def test_evidence_fingerprint_is_stable_and_json_serializable() -> None:
    """非证据字段和等价匹配表示不能改变证据指纹。"""
    content_candidate = DetectionCandidate(
        role="precision",
        direction="request",
        protocol="http",
        method="GET",
        features=(
            DetectionFeature(
                buffer="http.uri.raw",
                content=" WHOAMI ",
                nocase=False,
            ),
            DetectionFeature(
                buffer="http.uri.raw",
                content="../etc/passwd",
            ),
        ),
        dynamic_fields=("Host",),
        reason="精确候选",
    )
    pcre_candidate = DetectionCandidate(
        role="robust",
        direction="request",
        protocol="http",
        method=None,
        features=(
            DetectionFeature(
                buffer="http.uri",
                content="%2e%2e%2fetc%2fpasswd",
            ),
            DetectionFeature(buffer="http.uri", pcre="/whoami/i"),
        ),
        dynamic_fields=("Cookie", "Content-Length"),
        reason="完全不同的说明",
    )

    fingerprint = evidence_fingerprint(content_candidate)

    assert fingerprint == evidence_fingerprint(pcre_candidate)
    assert json.loads(json.dumps(fingerprint, ensure_ascii=False)) == fingerprint
    assert evidence_fingerprint_id(content_candidate) == evidence_fingerprint_id(
        pcre_candidate
    )
    assert evidence_fingerprint_id(content_candidate).startswith("efp:v1:")


def test_novel_evidence_exposes_only_new_exploit_semantics() -> None:
    """novel evidence 应剔除基线已经使用的利用证据。"""
    baseline = DetectionCandidate(
        role="precision",
        direction="request",
        protocol="http",
        method="GET",
        features=(DetectionFeature(buffer="http.request_body", content="whoami"),),
        dynamic_fields=(),
        reason="基线",
    )
    candidate = DetectionCandidate(
        role="robust",
        direction="request",
        protocol="http",
        method=None,
        features=(
            DetectionFeature(buffer="http.request_body", content="WHOAMI"),
            DetectionFeature(buffer="http.request_body", content="/bin/sh"),
        ),
        dynamic_fields=(),
        reason="鲁棒候选",
    )

    all_exploit = candidate_evidence_set(candidate, exploit_only=True)
    new_exploit = novel_evidence(candidate, (baseline,), exploit_only=True)

    assert len(all_exploit) == 2
    assert len(new_exploit) == 1
    assert new_exploit < all_exploit


def test_escaped_pcre_markers_are_exploit_evidence() -> None:
    """PCRE 转义不能隐藏目录遍历等明确利用语义。"""
    candidate = DetectionCandidate(
        role="robust",
        direction="request",
        protocol="http",
        method=None,
        features=(
            DetectionFeature(
                buffer="http.uri.raw",
                pcre=r"/(?:\.\.\/)+etc\/passwd/i",
            ),
        ),
        dynamic_fields=(),
        reason="目录遍历正则",
    )

    assert candidate_evidence_set(candidate, exploit_only=True)


def test_detection_plan_rejects_pcre_without_same_buffer_content_anchor() -> None:
    """模型计划中的裸 PCRE 必须在进入 lint 前按同一契约拒绝。"""
    values = [_candidate_data(role) for role in CANDIDATE_ROLES]
    values[1]["features"] = [
        {
            "buffer": "http.uri.raw",
            "pcre": r"/(?i)(?:file:|file%3a)(?:\/|%2f){2,3}etc/",
        }
    ]

    with pytest.raises(DetectionSchemaError, match="content 锚点"):
        parse_detection_data({"candidates": values})


def test_detection_plan_accepts_content_then_pcre_in_same_buffer() -> None:
    """稳定 content 后接同 buffer PCRE 是合法的 Robust 结构。"""
    values = [_candidate_data(role) for role in CANDIDATE_ROLES]
    values[1]["features"] = [
        {"buffer": "http.uri.raw", "content": "/viewPDF", "nocase": True},
        {
            "buffer": "http.uri.raw",
            "pcre": r"/(?i)(?:file:|file%3a)(?:\/|%2f){2,3}etc/",
        },
    ]

    plan = parse_detection_data({"candidates": values})

    assert plan.candidates[1].features[1].pcre is not None
    assert not {
        issue.code
        for issue in lint_candidate(plan.candidates[1])
        if issue.code == "UNANCHORED_PCRE"
    }


def test_precision_and_robust_reject_cosmetic_differences() -> None:
    """A/B 只调整大小写、buffer 表示和元数据时必须拒绝。"""
    values = [_candidate_data(role) for role in CANDIDATE_ROLES]
    precision_feature = values[0]["features"][0]
    assert isinstance(precision_feature, dict)
    robust = deepcopy(values[0])
    robust.update(
        {
            "role": "robust",
            "detection_scope": "case_specific",
            "method": None,
            "dynamic_fields": ["Cookie", "Content-Length"],
            "reason": "改写说明不能制造新证据",
        }
    )
    robust_feature = robust["features"][0]
    assert isinstance(robust_feature, dict)
    robust_feature["buffer"] = "http.uri"
    robust_feature["content"] = str(precision_feature["content"]).upper()
    robust_feature["nocase"] = False
    values[1] = robust

    with pytest.raises(DetectionSchemaError, match="不算独立候选"):
        parse_detection_data({"candidates": values})

    valid_plan = parse_detection_data(
        {"candidates": [_candidate_data(role) for role in CANDIDATE_ROLES]}
    )
    cosmetic_robust = replace(
        valid_plan.candidates[1],
        features=valid_plan.candidates[0].features,
        method=None,
        reason="只改说明",
        dynamic_fields=("Cookie",),
    )
    with pytest.raises(ValueError, match="不算独立候选"):
        compile_candidates(
            (
                valid_plan.candidates[0],
                cosmetic_robust,
                valid_plan.candidates[2],
            )
        )


def test_precision_requires_a_real_endpoint_anchor() -> None:
    """URI 中只有攻击值或参数名不能冒充 Precision 的 endpoint。"""
    values = [_candidate_data(role) for role in CANDIDATE_ROLES]
    values[0]["features"] = [
        {"buffer": "http.uri.raw", "content": "../etc/passwd"},
        {"buffer": "http.uri.raw", "content": "path="},
    ]

    with pytest.raises(DetectionSchemaError, match="endpoint 锚点"):
        parse_detection_data({"candidates": values})


def test_precision_and_robust_allow_meaningful_feature_tradeoff() -> None:
    """B 保留最小 endpoint，减少参数和具体 payload 绑定。"""
    values = [_candidate_data(role) for role in CANDIDATE_ROLES]
    precision = values[0]
    precision["features"] = [
        {"buffer": "http.uri.raw", "content": "/download"},
        {"buffer": "http.uri.raw", "content": "../etc/passwd"},
    ]
    robust = deepcopy(precision)
    robust.update(
        {
            "role": "robust",
            "method": None,
            "features": [
                {"buffer": "http.uri.raw", "content": "/download"},
                {"buffer": "http.uri.raw", "content": "../"}
            ],
        }
    )
    values[1] = robust

    plan = parse_detection_data({"candidates": values})

    assert plan.candidates[1].features == (
        DetectionFeature(buffer="http.uri.raw", content="/download"),
        DetectionFeature(buffer="http.uri.raw", content="../"),
    )


def test_alternative_request_requires_at_least_one_independent_exploit_evidence() -> None:
    """C 使用 request 时可以共享锚点，但至少要增加一个独立利用证据。"""
    values = [_candidate_data(role) for role in CANDIDATE_ROLES]
    alternative = values[2]
    alternative.update(
        {
            "direction": "request",
            "detection_scope": "case_specific",
            "method": None,
            "features": [
                {"buffer": "http.uri.raw", "content": "../etc/passwd"},
                {"buffer": "http.request_body", "content": "/bin/sh"},
            ],
        }
    )

    plan = parse_detection_data({"candidates": values})

    assert len(plan.candidates[2].features) == 2

    alternative["features"] = [
        {"buffer": "http.uri.raw", "content": "../etc/passwd"}
    ]
    with pytest.raises(
        DetectionSchemaError,
        match="相同证据集合|尚未使用的独立利用证据",
    ):
        parse_detection_data({"candidates": values})


def test_reference_metrics_are_observations_not_decision_proof() -> None:
    """动态字段不影响成本，旧启发式值明确标记为仅供参考。"""
    validation = {
        "positive_coverage": 0.75,
        "false_positive_count": 1,
    }
    base_complexity = {"pcre_count": 1, "dynamic_field_count": 0}
    detailed_complexity = {"pcre_count": 1, "dynamic_field_count": 7}

    base = _candidate_reference_metrics(validation, base_complexity)
    detailed = _candidate_reference_metrics(validation, detailed_complexity)
    assert base == detailed
    assert base["decision_authority"] == "reference_only"


def test_success_indicator_cannot_replace_case_specific_primary_rule() -> None:
    """补充成功指标即使满分，也不能抢走漏洞特异主规则。"""
    selected = _deterministic_primary_fallback(
        [
            {
                "candidate_index": 1,
                "detection_scope": "case_specific",
                "validation": {"passed": False},
                "passed": False,
                "reference_metrics": {
                    "positive_coverage": 0.85714,
                    "false_positive_count": 0,
                },
                "complexity": {"estimated_cost": 6},
            },
            {
                "candidate_index": 3,
                "detection_scope": "success_indicator",
                "validation": {"passed": True},
                "passed": True,
                "reference_metrics": {
                    "positive_coverage": 1.0,
                    "false_positive_count": 0,
                },
                "complexity": {"estimated_cost": 3},
            },
        ]
    )

    assert selected is not None
    assert selected["candidate_index"] == 1


def test_sample_oracle_targets_rule_direction_and_scope() -> None:
    contract = {
        123: ("request", "case_specific"),
        124: ("request", "case_specific"),
        125: ("response", "success_indicator"),
    }
    sids = set(contract)

    assert _sample_expected_sids("request_detection", sids, contract) == {123, 124}
    assert _sample_expected_sids("response_detection", sids, contract) == {125}
    assert _sample_expected_sids("transaction_specificity", sids, contract) == {
        123,
        124,
    }
    assert _sample_expected_sids("generic", sids, contract) == sids


def test_candidate_validation_ignores_samples_outside_its_oracle() -> None:
    batch = {
        "passed": False,
        "error_code": "NO_POSITIVE_MATCH",
        "errors": [],
        "warnings": [],
        "quality_warnings": [],
        "positive_matched_sids": [123, 125],
        "negative_matched_sids": [],
        "sample_results": [
            {
                "name": "positive-request",
                "expected": "alert",
                "expected_any_sids": [123, 124],
                "matched_sids": [123, 125],
                "passed": True,
                "applicable": True,
            },
            {
                "name": "positive-response",
                "expected": "alert",
                "expected_any_sids": [125],
                "matched_sids": [123, 125],
                "passed": True,
                "applicable": True,
            },
        ],
    }

    request_result = _candidate_validation(batch, 123)  # type: ignore[arg-type]
    response_result = _candidate_validation(batch, 125)  # type: ignore[arg-type]

    assert request_result["positive_coverage"] == 1.0
    assert response_result["positive_coverage"] == 1.0
    assert request_result["sample_results"][1]["applicable"] is False
    assert response_result["sample_results"][0]["applicable"] is False

    remapped = _remap_validation_sid(request_result, 123, 900001)
    assert remapped["sample_results"][0]["expected_any_sids"] == [900001]
    assert remapped["sample_results"][1]["expected_any_sids"] == []


def test_response_candidate_requires_positive_and_negative_response_oracles() -> None:
    batch = {
        "passed": True,
        "error_code": None,
        "errors": [],
        "warnings": [],
        "quality_warnings": [],
        "positive_matched_sids": [125],
        "negative_matched_sids": [],
        "sample_results": [
            {
                "name": "positive-original",
                "expected": "alert",
                "validates": "generic",
                "expected_any_sids": [125],
                "matched_sids": [125],
                "passed": True,
                "applicable": True,
            },
            {
                "name": "negative-generic",
                "expected": "no_alert",
                "validates": "generic",
                "expected_any_sids": [125],
                "matched_sids": [],
                "passed": True,
                "applicable": True,
            },
        ],
    }

    result = _candidate_validation(batch, 125, direction="response")  # type: ignore[arg-type]

    assert result["passed"] is False
    assert result["error_code"] == "RESPONSE_ORACLE_REQUIRED"
    assert "正向响应变体和近似负响应变体" in result["errors"][-1]


def test_response_candidate_passes_with_both_response_oracles() -> None:
    batch = {
        "passed": True,
        "error_code": None,
        "errors": [],
        "warnings": [],
        "quality_warnings": [],
        "positive_matched_sids": [125],
        "negative_matched_sids": [],
        "sample_results": [
            {
                "name": "positive-response-variant",
                "expected": "alert",
                "validates": "response_detection",
                "expected_any_sids": [125],
                "matched_sids": [125],
                "passed": True,
                "applicable": True,
            },
            {
                "name": "negative-response-decoy",
                "expected": "no_alert",
                "validates": "response_detection",
                "expected_any_sids": [125],
                "matched_sids": [],
                "passed": True,
                "applicable": True,
            },
        ],
    }

    result = _candidate_validation(batch, 125, direction="response")  # type: ignore[arg-type]

    assert result["passed"] is True
    assert result["error_code"] is None


def test_dynamic_fields_do_not_affect_estimated_cost() -> None:
    """填写更多动态字段不能增加编译器估算的规则运行代价。"""
    candidate = DetectionCandidate(
        role="precision",
        direction="request",
        protocol="http",
        method="GET",
        features=(
            DetectionFeature(
                buffer="http.uri.raw",
                content="path=..\\Windows\\win.ini",
                nocase=True,
            ),
        ),
        dynamic_fields=(),
        reason="目录遍历值能够区分攻击请求",
    )
    detailed_candidate = replace(
        candidate,
        dynamic_fields=("Host", "Content-Length", "Cookie"),
    )

    base = compile_candidate(candidate, sid=123)
    detailed = compile_candidate(detailed_candidate, sid=124)

    assert base.complexity.dynamic_field_count == 0
    assert detailed.complexity.dynamic_field_count == 3
    assert base.complexity.estimated_cost == detailed.complexity.estimated_cost


def test_prompt_candidate_count_and_buffers_follow_shared_contract() -> None:
    """提示词必须由共享候选范围和模型可选 buffer 集合生成。"""
    count_rule = f"输出 {MIN_CANDIDATES}～{MAX_CANDIDATES} 个真正不同的 detection strategies"
    buffer_rule = next(
        line for line in SYSTEM_PROMPT.splitlines() if "buffer 只能从这些值选择" in line
    )

    assert count_rule in SYSTEM_PROMPT
    assert '"detection_scope": "case_specific"' in SYSTEM_PROMPT
    assert '"detection_scope": "success_indicator"' in SYSTEM_PROMPT
    assert "robust：必须保留最小 endpoint 身份锚点" in SYSTEM_PROMPT
    assert "semantic_testcases 可省略" in SYSTEM_PROMPT
    assert "pcre 不能是该 buffer 的首个或唯一特征" in SYSTEM_PROMPT
    assert all(buffer in buffer_rule for buffer in MODEL_FEATURE_BUFFERS)
    assert all(buffer not in buffer_rule for buffer in FORBIDDEN_MODEL_FEATURE_BUFFERS)


def test_historical_strategy_context_removes_old_endpoints_and_rule_text() -> None:
    """历史策略只能传递通用经验，不能把旧接口或规则文本注入新候选。"""

    class CaptureModel:
        def __init__(self) -> None:
            self.messages: list[object] = []

        def invoke(self, messages: list[object]) -> object:
            self.messages = messages
            return type("Response", (), {"content": "{}"})()

    model = CaptureModel()
    extract_detection_features(
        "新的路径遍历漏洞",
        "file=../../etc/passwd",
        "GET /new?file=../../etc/passwd HTTP/1.1\r\nHost: current\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        model=model,
        strategy_context=[
            {
                "cluster_id": "strategy:v1:test",
                "exploit_families": ["path_traversal"],
                "buffers": ["http.uri.raw"],
                "representation_variants": [
                    "/old-download?path=../etc/passwd"
                ],
                "summary": {
                    "family": "Path Traversal",
                    "representation_variants": [
                        "/old-download?path=../etc/passwd"
                    ],
                },
                "endpoints": ["/old-download"],
                "parameters": ["path"],
                "raw_rule": "alert http any any -> any any (...) ",
            }
        ],
    )

    task = str(getattr(model.messages[-1], "content", ""))
    assert "strategy:v1:test" in task
    assert "path_traversal" in task
    assert "/old-download" not in task
    assert "path=" not in task
    assert "../etc/passwd" in task
    assert "raw_rule" not in task


@pytest.mark.parametrize("buffer", sorted(MODEL_FEATURE_BUFFERS))
def test_each_prompt_buffer_passes_lint_direction_check(buffer: str) -> None:
    """模型白名单不能包含会被 lint 必然拒绝的 sticky buffer。"""
    direction = "response" if buffer in RESPONSE_BUFFERS else "request"
    method = "GET" if direction == "request" else None
    candidate = DetectionCandidate(
        role="precision",
        direction=direction,
        protocol="http",
        method=method,
        features=(
            DetectionFeature(buffer=buffer, content="../etc/passwd"),
        ),
        dynamic_fields=(),
        reason="契约测试",
    )

    issues = lint_candidate(candidate)

    assert not {
        issue.code
        for issue in issues
        if issue.code in {"BUFFER_DIRECTION_MISMATCH", "METHOD_BUFFER_NOT_ALLOWED"}
    }
    if buffer in REQUEST_BUFFERS:
        assert direction == "request"
