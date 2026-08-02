from __future__ import annotations

import json
from copy import deepcopy
from dataclasses import replace

import pytest

from coverage_graph import analyze_rule_coverage
from detection_strategy import (
    build_strategy_catalog,
    build_strategy_clusters,
    infer_exploit_families,
    retrieve_strategy_clusters,
    sanitize_representation_variants,
    summarize_strategy_cluster,
    validate_strategy_catalog,
)
from rule_ir import parse_suricata_rules


_RULES = """
alert http any any -> any any (flow:established,to_server; http.uri; content:"/download"; http.uri; content:"../etc/passwd"; sid:800; rev:1;)
alert http any any -> any any (flow:established,to_server; http.uri.raw; content:"/preview"; http.uri.raw; content:"%252e%252e%252fetc%252fpasswd"; sid:801; rev:1;)
alert http any any -> any any (flow:established,to_server; http.request_body; content:"whoami"; sid:802; rev:1;)
"""

_COMBINED_RULES = r"""
alert http any any -> any any (flow:established,to_server; http.uri.raw; content:"/old-api?path=../etc/passwd"; sid:810; rev:1;)
alert http any any -> any any (flow:established,to_server; http.uri.raw; pcre:"/\/legacy\?file=(?:\.\.\/)+etc\/passwd/i"; sid:811; rev:1;)
"""


def _coverage():
    return analyze_rule_coverage(
        _RULES,
        [
            {"name": "traversal-1", "expected": "alert", "matched_sids": [800, 801]},
            {"name": "command-1", "expected": "alert", "matched_sids": [802]},
            {"name": "negative-1", "expected": "no_alert", "matched_sids": []},
        ],
    )


def _combined_coverage():
    return analyze_rule_coverage(
        _COMBINED_RULES,
        [
            {
                "name": "combined-traversal",
                "expected": "alert",
                "matched_sids": [810, 811],
            },
            {"name": "negative", "expected": "no_alert", "matched_sids": []},
        ],
    )


def _valid_catalog() -> dict[str, object]:
    return {
        "version": 1,
        "clusters": [
            {
                "cluster_id": "strategy:v1:path",
                "exploit_families": ["path_traversal"],
                "recommended_sids": [900],
                "buffers": ["http.uri.raw"],
                "endpoints": ["/old-api"],
                "parameters": ["path"],
                "representation_variants": ["/old-api?path=../etc/passwd"],
                "summary": None,
            }
        ],
    }


def test_strategy_clusters_group_representation_variants_without_endpoint_binding() -> None:
    rules = parse_suricata_rules(_RULES)
    clusters = build_strategy_clusters(rules, _coverage())

    traversal = next(
        cluster for cluster in clusters if cluster.exploit_families == ("path_traversal",)
    )
    assert traversal.rule_sids == (800, 801)
    assert traversal.endpoints == ("/download", "/preview")
    assert "../etc/passwd" in traversal.representation_variants
    assert traversal.positive_samples == ("traversal-1",)


def test_combined_content_and_pcre_strip_historical_bindings() -> None:
    """组合 content/PCRE 进入策略簇前必须剥离旧 endpoint 和参数名。"""
    clusters = build_strategy_clusters(
        parse_suricata_rules(_COMBINED_RULES),
        _combined_coverage(),
    )
    traversal = next(
        cluster for cluster in clusters if cluster.exploit_families == ("path_traversal",)
    )
    rendered = "\n".join(traversal.representation_variants)

    assert "old-api" not in rendered
    assert "legacy" not in rendered
    assert "path=" not in rendered
    assert "file=" not in rendered
    assert "passwd" in rendered
    assert sanitize_representation_variants(
        ("/old-api?path=../etc/passwd",),
        endpoints=("/old-api",),
        parameters=("path",),
    ) == ("../etc/passwd",)


def test_strategy_catalog_retrieval_uses_exploit_family_not_endpoint() -> None:
    catalog = build_strategy_catalog(parse_suricata_rules(_RULES), _coverage())

    results = retrieve_strategy_clusters(
        catalog,
        "GET /new-api?file=../../etc/shadow HTTP/1.1",
    )

    assert results
    assert results[0]["exploit_families"] == ("path_traversal",)
    assert infer_exploit_families("cmd=whoami") == ("command_execution",)
    assert infer_exploit_families("file=%252e%252e%252fetc%252fpasswd") == (
        "path_traversal",
    )


def test_strategy_clusters_and_retrieval_respect_detection_scope() -> None:
    rules = parse_suricata_rules(
        """
alert http any any -> any any (flow:to_server; http.uri; content:"/a"; content:"../etc/passwd"; metadata:detection_scope case_specific; sid:820;)
alert http any any -> any any (flow:to_server; http.uri; content:"/b"; content:"../etc/passwd"; metadata:detection_scope exploit_family; sid:821;)
alert http any any -> any any (flow:to_client; file_data; content:"root:x:0:0"; metadata:detection_scope success_indicator; sid:822;)
"""
    )
    coverage = analyze_rule_coverage(
        rules,
        [
            {
                "name": "positive",
                "expected": "alert",
                "matched_sids": [820, 821, 822],
            },
            {"name": "negative", "expected": "no_alert", "matched_sids": []},
        ],
    )
    clusters = build_strategy_clusters(rules, coverage)

    assert {cluster.detection_scope for cluster in clusters} == {
        "case_specific",
        "exploit_family",
        "success_indicator",
    }

    catalog = build_strategy_catalog(rules, coverage)
    success_query = "root:x:0:0:root:/root:/bin/bash"
    default_results = retrieve_strategy_clusters(catalog, success_query)
    all_results = retrieve_strategy_clusters(
        catalog,
        success_query,
        include_success_indicators=True,
    )

    assert all(
        item.get("detection_scope") != "success_indicator"
        for item in default_results
    )
    assert any(
        item.get("detection_scope") == "success_indicator"
        for item in all_results
    )


def test_catalog_and_retrieval_exclude_eliminated_clusters() -> None:
    """recommended_sids 为空的策略簇不能进入 catalog 或检索结果。"""
    coverage = replace(_coverage(), recommended_sids=(802,))
    catalog = build_strategy_catalog(parse_suricata_rules(_RULES), coverage)

    assert catalog["clusters"]
    assert all(item["recommended_sids"] for item in catalog["clusters"])
    assert all(
        item["exploit_families"] != ("path_traversal",)
        for item in catalog["clusters"]
    )

    external = _valid_catalog()
    external_cluster = external["clusters"][0]
    assert isinstance(external_cluster, dict)
    external_cluster["recommended_sids"] = []
    assert retrieve_strategy_clusters(
        external,
        "GET /new?file=../../etc/passwd HTTP/1.1",
    ) == []


def test_retrieval_sanitizes_legacy_combined_variants() -> None:
    """旧 catalog 即使仍有组合特征，检索结果也只能携带利用表示。"""
    results = retrieve_strategy_clusters(
        _valid_catalog(),
        "GET /new?file=../../etc/passwd HTTP/1.1",
    )

    assert results[0]["representation_variants"] == ("../etc/passwd",)


@pytest.mark.parametrize(
    ("field", "invalid", "message"),
    [
        pytest.param(
            "exploit_families",
            "path_traversal",
            r"clusters\[0\]\.exploit_families 必须是字符串数组",
            id="family-不是数组",
        ),
        pytest.param(
            "recommended_sids",
            900,
            r"clusters\[0\]\.recommended_sids 必须是 SID 整数数组",
            id="sid-不是数组",
        ),
        pytest.param(
            "recommended_sids",
            [True],
            r"clusters\[0\]\.recommended_sids\[0\] 必须是有效 SID",
            id="sid-bool",
        ),
        pytest.param(
            "representation_variants",
            {"value": "../"},
            r"clusters\[0\]\.representation_variants 必须是字符串数组",
            id="variant-不是数组",
        ),
    ],
)
def test_catalog_internal_fields_raise_friendly_validation_errors(
    field: str,
    invalid: object,
    message: str,
) -> None:
    """坏字段必须报告 catalog 路径，不能泄漏原生 len()/类型异常。"""
    catalog = deepcopy(_valid_catalog())
    cluster = catalog["clusters"][0]
    assert isinstance(cluster, dict)
    cluster[field] = invalid

    with pytest.raises(ValueError, match=message):
        validate_strategy_catalog(catalog)


def test_catalog_rejects_unknown_cluster_fields_and_bad_summary() -> None:
    """未知内部字段和损坏的 summary 都必须严格拒绝。"""
    unknown = deepcopy(_valid_catalog())
    unknown_cluster = unknown["clusters"][0]
    assert isinstance(unknown_cluster, dict)
    unknown_cluster["raw_rule"] = "alert http ..."
    with pytest.raises(ValueError, match="包含未知字段：raw_rule"):
        retrieve_strategy_clusters(unknown, "../etc/passwd")

    bad_summary = deepcopy(_valid_catalog())
    summary_cluster = bad_summary["clusters"][0]
    assert isinstance(summary_cluster, dict)
    summary_cluster["summary"] = {
        "family": "Path Traversal",
        "core_strategy": "traversal semantic",
        "representation_variants": [],
        "do_not_bind": 7,
    }
    with pytest.raises(ValueError, match=r"summary\.do_not_bind 必须是字符串数组"):
        retrieve_strategy_clusters(bad_summary, "../etc/passwd")


class _FakeModel:
    def __init__(self, value: object) -> None:
        self.value = value

    def invoke(self, _messages: list[object]) -> object:
        return self.value


def test_llm_last_mile_can_only_fill_fixed_strategy_schema() -> None:
    cluster = next(
        item
        for item in build_strategy_clusters(parse_suricata_rules(_RULES), _coverage())
        if item.endpoints
    )
    payload = json.dumps(
        {
            "family": "Command Injection",
            "core_strategy": "匹配请求中的命令执行语义",
            "representation_variants": ["shell command"],
            "do_not_bind": ["Host", "Content-Length"],
        },
        ensure_ascii=False,
    )

    summary = summarize_strategy_cluster(cluster, model=_FakeModel(payload))

    assert summary.family == "Command Injection"
    assert summary.do_not_bind == ("Host", "Content-Length")

    invalid = json.dumps(
        {
            "family": "X",
            "core_strategy": "Y",
            "representation_variants": [],
            "do_not_bind": [],
            "rules": ["drop all"],
        }
    )
    with pytest.raises(ValueError, match="固定 schema"):
        summarize_strategy_cluster(cluster, model=_FakeModel(invalid))

    copied_endpoint = json.dumps(
        {
            "family": "X",
            "core_strategy": f"固定匹配 {cluster.endpoints[0]}",
            "representation_variants": [],
            "do_not_bind": [],
        },
        ensure_ascii=False,
    )
    with pytest.raises(ValueError, match="不得复制具体 endpoint"):
        summarize_strategy_cluster(cluster, model=_FakeModel(copied_endpoint))
