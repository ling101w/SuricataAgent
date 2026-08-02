from __future__ import annotations

import json

import pytest

from evidence_fingerprint import evidence_set, rule_logic_fingerprint_id

from rule_ir import (
    RuleIRParseError,
    parse_suricata_rule,
    parse_suricata_rules,
    rule_ir_to_dict,
    serialize_rule_ir,
)


def test_parse_request_rule_with_sticky_buffers_and_evidence() -> None:
    """请求规则应还原 method、十六进制 content 和分类检测证据。"""
    rule = parse_suricata_rule(
        r'''
        alert http any any -> any any (
            msg:"Traversal request";
            flow:established,to_server;
            http.method; content:"GET";
            http.uri.raw;
            content:"/download?path=|2E 2E 5C|Windows|5C|win.ini"; nocase;
            pcre:"/win\.ini$/i";
            classtype:web-application-attack;
            sid:123; rev:2;
            metadata:attack_target Server, created_at 2026_08_02;
        )
        '''
    )

    assert rule.sid == 123
    assert rule.direction == "request"
    assert rule.detection_scope == "case_specific"
    assert rule.method == "GET"
    assert rule.msg == "Traversal request"
    assert rule.rev == 2
    assert rule.metadata == ("attack_target Server", "created_at 2026_08_02")
    assert len(rule.features) == 2
    assert rule.features[0].buffer == "http.uri.raw"
    assert rule.features[0].content == b"/download?path=..\\Windows\\win.ini"
    assert rule.features[0].nocase is True
    assert rule.features[1].pcre == r"/win\.ini$/i"
    assert rule.evidence.endpoint == ("/download",)
    assert rule.evidence.parameter == ("path",)
    assert rule.evidence.exploit == (
        r"/download?path=..\Windows\win.ini",
        r"/win\.ini$/i",
    )
    assert rule.evidence.success == ()


def test_parse_response_rule() -> None:
    """响应 sticky buffer 应确定 to_client 方向并成为响应证据。"""
    rule = parse_suricata_rule(
        'alert http any any -> any any '
        '(flow:established,to_client; file_data; '
        'content:"[fonts]|0A|[extensions]"; sid:124; rev:1;)'
    )

    assert rule.direction == "response"
    assert rule.detection_scope == "success_indicator"
    assert rule.method is None
    assert rule.features[0].buffer == "file_data"
    assert rule.features[0].content == b"[fonts]\n[extensions]"
    assert rule.evidence.endpoint == ()
    assert rule.evidence.parameter == ()
    assert rule.evidence.exploit == ()
    assert rule.evidence.success == ("[fonts]\n[extensions]",)


def test_parse_multiple_rules_and_serialize_json() -> None:
    """多规则解析保持顺序，序列化结果只包含 JSON 基础类型。"""
    rules = parse_suricata_rules(
        """
        # 请求侧规则
        alert http any any -> any any (flow:to_server; http.uri;
          content:"/api?cmd=whoami"; sid:200; rev:1;)

        # 响应侧规则
        alert http any any -> any any (flow:to_client; http.stat_code;
          content:"500"; sid:201; rev:3;)
        """
    )

    assert [rule.sid for rule in rules] == [200, 201]
    assert [rule.direction for rule in rules] == ["request", "response"]
    assert rule_ir_to_dict(rules[0])["features"][0]["content_hex"] == "2F6170693F636D643D77686F616D69"

    payload = json.loads(serialize_rule_ir(rules, indent=None))
    assert [item["sid"] for item in payload["rules"]] == [200, 201]
    assert payload["rules"][0]["evidence"] == {
        "endpoint": ["/api"],
        "parameter": ["cmd"],
        "exploit": ["/api?cmd=whoami"],
        "success": [],
    }


def test_detection_scope_metadata_is_parsed() -> None:
    rule = parse_suricata_rule(
        'alert http any any -> any any (flow:to_server; http.uri; '
        'content:"/download"; metadata:detection_scope exploit_family; sid:202;)'
    )

    assert rule.detection_scope == "exploit_family"
    assert rule_ir_to_dict(rule)["detection_scope"] == "exploit_family"


def test_content_escaped_characters_are_decoded() -> None:
    """引号、分号、反斜杠和竖线转义必须精确还原。"""
    rule = parse_suricata_rule(
        r'''alert http any any -> any any (
        msg:"A \"quoted\" rule"; flow:to_server; http.request_body;
        content:"quote\" semi\; slash\\ pipe\|"; nocase; sid:300;)'''
    )

    assert rule.msg == 'A "quoted" rule'
    assert rule.features[0].content == b'quote" semi; slash\\ pipe|'
    assert rule.features[0].nocase is True


def test_parse_legacy_content_and_pcre_http_buffers() -> None:
    """旧式 content modifier 与 PCRE buffer flag 必须进入正确的现代 buffer。"""
    rule = parse_suricata_rule(
        r'''alert http any any -> any any (
        flow:established,to_server;
        content:"POST"; http_method;
        content:"/legacy?path="; http_uri;
        pcre:"/\.\.\/etc\/passwd/U";
        sid:301;)'''
    )

    assert rule.direction == "request"
    assert rule.method == "POST"
    assert [feature.buffer for feature in rule.features] == [
        "http.uri",
        "http.uri",
    ]
    assert rule.features[1].pcre == r"/\.\.\/etc\/passwd/U"
    assert rule.evidence.endpoint == ("/legacy",)
    assert r"/\.\.\/etc\/passwd/U" in rule.evidence.exploit


def test_conflicting_pcre_http_buffer_modifiers_are_rejected() -> None:
    with pytest.raises(RuleIRParseError, match="多个冲突"):
        parse_suricata_rule(
            r'''alert http any any -> any any (
            flow:to_server; pcre:"/attack/UI"; sid:302;)'''
        )


def test_negated_feature_has_distinct_fingerprint_and_is_not_exploit_evidence() -> None:
    positive = parse_suricata_rule(
        'alert http any any -> any any (flow:to_server; http.uri; '
        'content:"../etc/passwd"; sid:303;)'
    )
    negated = parse_suricata_rule(
        'alert http any any -> any any (flow:to_server; http.uri; '
        'content:!"../etc/passwd"; sid:304;)'
    )

    assert evidence_set(positive) != evidence_set(negated)
    assert evidence_set(negated, exploit_only=True) == frozenset()
    assert rule_logic_fingerprint_id(positive) != rule_logic_fingerprint_id(negated)


@pytest.mark.parametrize(
    "rules, expected_message",
    [
        (
            'alert http any any -> any any (flow:to_server; http.uri; content:"/x";)',
            "规则缺少 sid",
        ),
        (
            'alert http any any -> any any (flow:to_server; http.uri; content:"|GG|"; sid:1;)',
            "十六进制块",
        ),
        (
            'alert http any any -> any any (flow:to_server; nocase; sid:1;)',
            "nocase 前没有",
        ),
        (
            'alert http any any -> any any (flow:to_client; http.uri; content:"/x"; sid:1;)',
            "冲突",
        ),
    ],
)
def test_invalid_rule_is_rejected(rules: str, expected_message: str) -> None:
    """不完整或语义冲突的规则不能生成部分 IR。"""
    with pytest.raises(RuleIRParseError, match=expected_message):
        parse_suricata_rule(rules)


def test_duplicate_sid_is_rejected_across_rules() -> None:
    """同一规则集中的 SID 必须唯一。"""
    rules = """
    alert http any any -> any any (flow:to_server; http.uri; content:"/one"; sid:7;)
    alert http any any -> any any (flow:to_client; file_data; content:"two"; sid:7;)
    """

    with pytest.raises(RuleIRParseError, match="SID 7 重复"):
        parse_suricata_rules(rules)
