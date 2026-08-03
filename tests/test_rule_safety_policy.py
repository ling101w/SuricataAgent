from __future__ import annotations

from validate_rules import RulePolicy, static_check_rules


STRICT_POLICY = RulePolicy(
    sid_start=123,
    max_rules=1,
    allowed_protocols=frozenset({"http"}),
    allowed_directions=frozenset({"->"}),
    required_flow_options=frozenset({"established", "to_server"}),
    require_rev=True,
    max_pcre_count=2,
    max_byte_jump_count=0,
)

SAFE_RULE = (
    'alert http any any -> any any (flow:established,to_server; '
    'http.uri; content:"/admin/upload"; sid:123; rev:1;)'
)


def test_strict_rule_safety_policy_accepts_bounded_request_rule() -> None:
    assert static_check_rules(SAFE_RULE, policy=STRICT_POLICY)["passed"] is True


def test_rule_safety_policy_rejects_side_effect_keywords() -> None:
    unsafe = SAFE_RULE.replace(
        "sid:123;",
        'dataset:set,blocked,type string,save state.txt; sid:123;',
    )

    result = static_check_rules(unsafe, policy=STRICT_POLICY)

    assert result["passed"] is False
    assert any("禁止关键字" in error and "dataset" in error for error in result["errors"])


def test_rule_safety_policy_rejects_weakened_flow_and_protocol() -> None:
    weakened = SAFE_RULE.replace("established,to_server", "to_server")
    wrong_protocol = SAFE_RULE.replace("alert http", "alert tcp")

    assert static_check_rules(weakened, policy=STRICT_POLICY)["passed"] is False
    assert static_check_rules(wrong_protocol, policy=STRICT_POLICY)["passed"] is False


def test_rule_safety_policy_rejects_byte_jump_and_high_risk_pcre() -> None:
    byte_jump = SAFE_RULE.replace("sid:123;", "byte_jump:4,0; sid:123;")
    nested_quantifier = SAFE_RULE.replace(
        "sid:123;",
        'pcre:"/(a+)+$/"; sid:123;',
    )

    byte_result = static_check_rules(byte_jump, policy=STRICT_POLICY)
    pcre_result = static_check_rules(nested_quantifier, policy=STRICT_POLICY)

    assert any("byte_jump" in error for error in byte_result["errors"])
    assert any("嵌套量词" in error for error in pcre_result["errors"])
