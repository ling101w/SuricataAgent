"""根据逐样本命中矩阵分析规则重复、包含关系和推荐保留集合。"""

from __future__ import annotations

from collections import defaultdict
from collections.abc import Mapping, Sequence
from dataclasses import asdict, dataclass
from itertools import combinations
import json
import re
from typing import Any, Literal

from evidence_fingerprint import evidence_fingerprint_id, rule_logic_fingerprint_id
from rule_ir import RuleIR, parse_suricata_rules
from rule_knowledge import DetectionScope


RelationKind = Literal[
    "text_duplicate",
    "logic_duplicate",
    "coverage_duplicate",
    "dominates",
]


@dataclass(frozen=True, slots=True)
class RuleProfile:
    """Coverage Graph 所需的最小规则描述。"""

    sid: int
    evidence_fingerprint: str
    logic_fingerprint: str
    normalized_text: str
    complexity: int
    direction: Literal["request", "response"] = "request"
    detection_scope: DetectionScope = "case_specific"
    pcre_count: int = 0

    def __post_init__(self) -> None:
        if not 1 <= self.sid <= 4_294_967_295:
            raise ValueError("sid 必须是有效的 Suricata SID")
        if not self.evidence_fingerprint or not self.logic_fingerprint:
            raise ValueError("evidence_fingerprint 和 logic_fingerprint 不能为空")
        if self.direction not in {"request", "response"}:
            raise ValueError("direction 必须是 request 或 response")
        if self.detection_scope not in {
            "case_specific",
            "exploit_family",
            "success_indicator",
        }:
            raise ValueError("detection_scope 无效")
        if self.complexity < 0 or self.pcre_count < 0:
            raise ValueError("complexity 和 pcre_count 不能为负数")


@dataclass(frozen=True, slots=True)
class CoverageNode:
    """一条规则在正负样本集合上的实际覆盖。"""

    sid: int
    direction: Literal["request", "response"]
    detection_scope: DetectionScope
    evidence_fingerprint: str
    logic_fingerprint: str
    positive_hits: tuple[str, ...]
    negative_hits: tuple[str, ...]
    complexity: int
    pcre_count: int

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CoverageRelation:
    """source 规则相对于 target 规则的可证明关系。"""

    source_sid: int
    target_sid: int
    kind: RelationKind
    reason: str

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class RuleRecommendation:
    """单条规则的保留结论及其依据。"""

    sid: int
    keep: bool
    reason_code: str
    reason: str
    replaced_by_sid: int | None = None

    def public_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True, slots=True)
class CoverageAnalysis:
    """完整 Coverage Graph 和确定性规则集优化结果。"""

    positive_samples: tuple[str, ...]
    negative_samples: tuple[str, ...]
    nodes: tuple[CoverageNode, ...]
    relations: tuple[CoverageRelation, ...]
    recommended_sids: tuple[int, ...]
    recommendations: tuple[RuleRecommendation, ...]
    covered_positive_samples: tuple[str, ...]
    uncovered_positive_samples: tuple[str, ...]
    false_positive_samples: tuple[str, ...]
    optimization_method: Literal["exact", "greedy"]

    def public_dict(self) -> dict[str, Any]:
        scope_by_sid = {
            node.sid: node.detection_scope
            for node in self.nodes
        }
        recommended_by_scope: dict[str, list[int]] = {}
        for sid in self.recommended_sids:
            scope = scope_by_sid.get(sid, "case_specific")
            recommended_by_scope.setdefault(scope, []).append(sid)
        return {
            "positive_samples": list(self.positive_samples),
            "negative_samples": list(self.negative_samples),
            "nodes": [node.public_dict() for node in self.nodes],
            "relations": [relation.public_dict() for relation in self.relations],
            "recommended_sids": list(self.recommended_sids),
            "recommended_by_scope": recommended_by_scope,
            "recommendations": [item.public_dict() for item in self.recommendations],
            "covered_positive_samples": list(self.covered_positive_samples),
            "uncovered_positive_samples": list(self.uncovered_positive_samples),
            "false_positive_samples": list(self.false_positive_samples),
            "optimization_method": self.optimization_method,
        }


def _sample_value(sample: object, key: str, default: object = None) -> object:
    if isinstance(sample, Mapping):
        return sample.get(key, default)
    return getattr(sample, key, default)


_MISSING = object()


def _sid_contract(value: object, path: str) -> frozenset[int]:
    """严格解析用于证明规则已参与回放的 SID 集合。"""
    if not isinstance(value, Sequence) or isinstance(value, (str, bytes)):
        raise ValueError(f"{path} 必须是 SID 数组")
    result: set[int] = set()
    for index, item in enumerate(value):
        if isinstance(item, bool) or not (
            isinstance(item, int) or isinstance(item, str) and item.isdigit()
        ):
            raise ValueError(f"{path}[{index}] 必须是正整数 SID")
        sid = int(item)
        if not 1 <= sid <= 4_294_967_295:
            raise ValueError(f"{path}[{index}] 必须是有效的 Suricata SID")
        result.add(sid)
    return frozenset(result)


def _validate_coverage_evidence(
    profiles: Sequence[RuleProfile],
    sample_results: Sequence[object],
    evaluated_sids: Sequence[int] | None,
) -> None:
    """拒绝无法证明当前全部规则已参与回放的覆盖输入。

    新版验证结果通过 ``expected_any_sids`` 携带规则集契约。旧结果没有该字段时，
    只有当前每个 SID 都至少真实命中过一次，才能保守确认报告属于这批规则。
    真正的全零命中需要 expected_any_sids 或调用方显式传入 evaluated_sids。
    """
    if not sample_results:
        raise ValueError("sample_results 不能为空，无法证明规则覆盖")

    known_sids = {profile.sid for profile in profiles}
    if evaluated_sids is not None:
        evaluated = _sid_contract(evaluated_sids, "evaluated_sids")
        missing = known_sids - evaluated
        if missing:
            raise ValueError(
                "evaluated_sids 未覆盖当前规则 SID："
                + "、".join(str(sid) for sid in sorted(missing))
            )
        return

    contract_union: set[int] = set()
    samples_with_contract = 0
    observed_known_sids: set[int] = set()
    for index, sample in enumerate(sample_results):
        expected_value = _sample_value(sample, "expected_any_sids", _MISSING)
        if expected_value is not _MISSING:
            samples_with_contract += 1
            contract_union.update(
                _sid_contract(
                    expected_value,
                    f"sample_results[{index}].expected_any_sids",
                )
            )
        matched_value = _sample_value(sample, "matched_sids", ())
        if isinstance(matched_value, Sequence) and not isinstance(
            matched_value, (str, bytes)
        ):
            observed_known_sids.update(
                sid
                for sid in (
                    int(value)
                    for value in matched_value
                    if not isinstance(value, bool)
                    and (isinstance(value, int) or str(value).isdigit())
                )
                if sid in known_sids
            )

    if samples_with_contract:
        if samples_with_contract != len(sample_results):
            raise ValueError(
                "sample_results 只有部分样本包含 expected_any_sids，覆盖证据不完整"
            )
        missing = known_sids - contract_union
        if missing:
            raise ValueError(
                "expected_any_sids 与当前规则 SID 不匹配，缺少："
                + "、".join(str(sid) for sid in sorted(missing))
            )
        return

    missing = known_sids - observed_known_sids
    if missing:
        raise ValueError(
            "旧格式 sample_results 无法证明当前规则 SID 已被完整评估，缺少："
            + "、".join(str(sid) for sid in sorted(missing))
        )


def _sample_matrix(
    profiles: Sequence[RuleProfile],
    sample_results: Sequence[object],
) -> tuple[
    tuple[str, ...],
    tuple[str, ...],
    dict[int, frozenset[str]],
    dict[int, frozenset[str]],
]:
    known_sids = {profile.sid for profile in profiles}
    positive_names: list[str] = []
    negative_names: list[str] = []
    positive_hits: dict[int, set[str]] = defaultdict(set)
    negative_hits: dict[int, set[str]] = defaultdict(set)
    seen_names: set[str] = set()

    for index, sample in enumerate(sample_results, start=1):
        if _sample_value(sample, "applicable", True) is False:
            continue
        name = str(_sample_value(sample, "name", f"sample-{index}"))
        if name in seen_names:
            raise ValueError(f"样本名称重复：{name}")
        seen_names.add(name)
        expected = str(_sample_value(sample, "expected", "alert"))
        if expected not in {"alert", "no_alert"}:
            raise ValueError(f"样本 {name} 的 expected 必须是 alert 或 no_alert")
        matched_value = _sample_value(sample, "matched_sids", ())
        if not isinstance(matched_value, Sequence) or isinstance(
            matched_value, (str, bytes)
        ):
            raise ValueError(f"样本 {name} 的 matched_sids 必须是数组")
        matched_sids = {
            int(value)
            for value in matched_value
            if isinstance(value, int) or str(value).isdigit()
        } & known_sids
        contract_value = _sample_value(sample, "expected_any_sids", _MISSING)
        if contract_value is not _MISSING:
            matched_sids &= _sid_contract(
                contract_value,
                f"sample_results[{index - 1}].expected_any_sids",
            )
        target = positive_hits if expected == "alert" else negative_hits
        names = positive_names if expected == "alert" else negative_names
        names.append(name)
        for sid in matched_sids:
            target[sid].add(name)

    return (
        tuple(positive_names),
        tuple(negative_names),
        {sid: frozenset(positive_hits[sid]) for sid in known_sids},
        {sid: frozenset(negative_hits[sid]) for sid in known_sids},
    )


def _profile_cost(profile: RuleProfile) -> tuple[int, int, int]:
    return profile.pcre_count, profile.complexity, profile.sid


def _relation_graph(
    profiles: Sequence[RuleProfile],
    positive_hits: Mapping[int, frozenset[str]],
    negative_hits: Mapping[int, frozenset[str]],
) -> tuple[CoverageRelation, ...]:
    relations: list[CoverageRelation] = []
    for left, right in combinations(profiles, 2):
        # 不同检测目标属于互补证据面，即使命中同一 PCAP 也不能互相替代。
        if (
            left.direction != right.direction
            or left.detection_scope != right.detection_scope
        ):
            continue
        left_positive = positive_hits[left.sid]
        right_positive = positive_hits[right.sid]
        left_negative = negative_hits[left.sid]
        right_negative = negative_hits[right.sid]

        if left.normalized_text and left.normalized_text == right.normalized_text:
            source, target = sorted((left, right), key=_profile_cost)
            relations.append(
                CoverageRelation(
                    source.sid,
                    target.sid,
                    "text_duplicate",
                    "规范化规则文本相同",
                )
            )
        elif (
            left.logic_fingerprint == right.logic_fingerprint
            and left_positive == right_positive
            and left_negative == right_negative
        ):
            source, target = sorted((left, right), key=_profile_cost)
            relations.append(
                CoverageRelation(
                    source.sid,
                    target.sid,
                    "logic_duplicate",
                    "检测证据指纹和样本覆盖完全相同",
                )
            )
        elif left_positive == right_positive and left_negative == right_negative:
            source, target = sorted((left, right), key=_profile_cost)
            relations.append(
                CoverageRelation(
                    source.sid,
                    target.sid,
                    "coverage_duplicate",
                    "检测逻辑不同，但当前 benchmark 上的 TP/FP 覆盖完全相同",
                )
            )

        for source, target in ((left, right), (right, left)):
            source_positive = positive_hits[source.sid]
            target_positive = positive_hits[target.sid]
            source_negative = negative_hits[source.sid]
            target_negative = negative_hits[target.sid]
            coverage_is_strictly_better = (
                source_positive != target_positive
                or source_negative != target_negative
            )
            source_cost = (source.pcre_count, source.complexity)
            target_cost = (target.pcre_count, target.complexity)
            cost_is_no_higher = source_cost <= target_cost
            cost_is_strictly_lower = source_cost < target_cost
            if (
                source_positive >= target_positive
                and source_negative <= target_negative
                and (
                    coverage_is_strictly_better
                    or cost_is_no_higher
                    and cost_is_strictly_lower
                )
            ):
                relations.append(
                    CoverageRelation(
                        source.sid,
                        target.sid,
                        "dominates",
                        "正样本覆盖不少、负样本误报不多且优化成本不高",
                    )
                )

    return tuple(
        sorted(
            relations,
            key=lambda item: (item.kind, item.source_sid, item.target_sid),
        )
    )


def _subset_objective(
    selected: Sequence[RuleProfile],
    negative_hits: Mapping[int, frozenset[str]],
) -> tuple[int, int, int, int, tuple[int, ...]]:
    false_positives = set().union(
        *(negative_hits[profile.sid] for profile in selected)
    )
    return (
        len(false_positives),
        len(selected),
        sum(profile.pcre_count for profile in selected),
        sum(profile.complexity for profile in selected),
        tuple(sorted(profile.sid for profile in selected)),
    )


def _exact_cover(
    profiles: Sequence[RuleProfile],
    target: frozenset[str],
    positive_hits: Mapping[int, frozenset[str]],
    negative_hits: Mapping[int, frozenset[str]],
) -> tuple[RuleProfile, ...]:
    best: tuple[RuleProfile, ...] | None = None
    best_objective: tuple[int, int, int, int, tuple[int, ...]] | None = None
    for size in range(1, len(profiles) + 1):
        for selected in combinations(profiles, size):
            covered = set().union(*(positive_hits[item.sid] for item in selected))
            if covered != target:
                continue
            objective = _subset_objective(selected, negative_hits)
            if best_objective is None or objective < best_objective:
                best = selected
                best_objective = objective
    return tuple(best or ())


def _greedy_cover(
    profiles: Sequence[RuleProfile],
    target: frozenset[str],
    positive_hits: Mapping[int, frozenset[str]],
    negative_hits: Mapping[int, frozenset[str]],
) -> tuple[RuleProfile, ...]:
    remaining = set(target)
    selected: list[RuleProfile] = []
    false_positives: set[str] = set()
    available = list(profiles)
    while remaining:
        useful = [item for item in available if positive_hits[item.sid] & remaining]
        if not useful:
            break
        choice = max(
            useful,
            key=lambda item: (
                len(positive_hits[item.sid] & remaining),
                -len(negative_hits[item.sid] - false_positives),
                -item.pcre_count,
                -item.complexity,
                -item.sid,
            ),
        )
        selected.append(choice)
        available.remove(choice)
        remaining -= positive_hits[choice.sid]
        false_positives |= negative_hits[choice.sid]

    # 逆序剔除不再贡献覆盖的规则，保证结果是 inclusion-minimal。
    for item in tuple(reversed(selected)):
        without = [candidate for candidate in selected if candidate.sid != item.sid]
        covered = set().union(
            *(positive_hits[candidate.sid] for candidate in without)
        )
        if covered == target:
            selected = without
    return tuple(sorted(selected, key=lambda item: item.sid))


def analyze_coverage(
    profiles: Sequence[RuleProfile],
    sample_results: Sequence[object],
    *,
    exact_limit: int = 16,
    evaluated_sids: Sequence[int] | None = None,
) -> CoverageAnalysis:
    """构建 Coverage Graph，并给出可复现的规则集优化建议。"""
    if not profiles:
        raise ValueError("profiles 不能为空")
    if exact_limit < 1:
        raise ValueError("exact_limit 必须大于 0")
    profile_list = list(profiles)
    if len({profile.sid for profile in profile_list}) != len(profile_list):
        raise ValueError("规则 SID 不能重复")
    _validate_coverage_evidence(profile_list, sample_results, evaluated_sids)

    positives, negatives, positive_hits, negative_hits = _sample_matrix(
        profile_list,
        sample_results,
    )
    nodes = tuple(
        CoverageNode(
            sid=profile.sid,
            direction=profile.direction,
            detection_scope=profile.detection_scope,
            evidence_fingerprint=profile.evidence_fingerprint,
            logic_fingerprint=profile.logic_fingerprint,
            positive_hits=tuple(sorted(positive_hits[profile.sid])),
            negative_hits=tuple(sorted(negative_hits[profile.sid])),
            complexity=profile.complexity,
            pcre_count=profile.pcre_count,
        )
        for profile in sorted(profile_list, key=lambda item: item.sid)
    )
    relations = _relation_graph(profile_list, positive_hits, negative_hits)

    replaceable: dict[int, tuple[int, str]] = {}
    relation_priority = {
        "text_duplicate": 0,
        "logic_duplicate": 1,
        "coverage_duplicate": 2,
        "dominates": 3,
    }
    for relation in sorted(
        relations,
        key=lambda item: (
            relation_priority[item.kind],
            item.target_sid,
            item.source_sid,
        ),
    ):
        if relation.kind in {
            "text_duplicate",
            "logic_duplicate",
            "coverage_duplicate",
        } and (
            positive_hits[relation.source_sid]
            < positive_hits[relation.target_sid]
            or negative_hits[relation.source_sid]
            > negative_hits[relation.target_sid]
        ):
            # 文本看似重复但实际覆盖不等时保留证据，不能让分类标签覆盖回放事实。
            continue
        replaceable.setdefault(
            relation.target_sid,
            (relation.source_sid, relation.kind),
        )

    selected_by_objective: list[RuleProfile] = []
    methods: list[Literal["exact", "greedy"]] = []
    objectives = sorted(
        {(item.detection_scope, item.direction) for item in profile_list}
    )
    for detection_scope, direction in objectives:
        objective_profiles = [
            item
            for item in profile_list
            if item.direction == direction
            and item.detection_scope == detection_scope
        ]
        if not objective_profiles:
            continue
        eligible = [
            item for item in objective_profiles if item.sid not in replaceable
        ]
        target = frozenset().union(
            *(positive_hits[profile.sid] for profile in objective_profiles)
        )
        if not target:
            objective_selected: tuple[RuleProfile, ...] = ()
            objective_method: Literal["exact", "greedy"] = "exact"
        elif len(eligible) <= exact_limit:
            objective_selected = _exact_cover(
                eligible,
                target,
                positive_hits,
                negative_hits,
            )
            objective_method = "exact"
        else:
            objective_selected = _greedy_cover(
                eligible,
                target,
                positive_hits,
                negative_hits,
            )
            objective_method = "greedy"
        selected_by_objective.extend(objective_selected)
        methods.append(objective_method)

    selected = tuple(sorted(selected_by_objective, key=lambda item: item.sid))
    method: Literal["exact", "greedy"] = (
        "greedy" if "greedy" in methods else "exact"
    )

    selected_sids = {item.sid for item in selected}
    recommendations: list[RuleRecommendation] = []
    reason_labels = {
        "text_duplicate": ("TEXT_DUPLICATE", "规范化文本重复"),
        "logic_duplicate": ("LOGIC_DUPLICATE", "检测逻辑重复"),
        "coverage_duplicate": ("COVERAGE_DUPLICATE", "当前样本覆盖重复"),
        "dominates": ("SUBSUMED", "被另一条规则包含且没有成本优势"),
    }
    for profile in sorted(profile_list, key=lambda item: item.sid):
        if profile.sid in selected_sids:
            recommendations.append(
                RuleRecommendation(profile.sid, True, "KEEP", "贡献推荐覆盖集合")
            )
            continue
        replacement = replaceable.get(profile.sid)
        if replacement is not None:
            replacement_sid, kind = replacement
            code, label = reason_labels[kind]
            recommendations.append(
                RuleRecommendation(
                    profile.sid,
                    False,
                    code,
                    label,
                    replacement_sid,
                )
            )
            continue
        recommendations.append(
            RuleRecommendation(
                profile.sid,
                False,
                "NOT_REQUIRED_FOR_COVERAGE",
                "不增加推荐集合的攻击样本覆盖",
            )
        )

    covered = frozenset().union(
        *(positive_hits[item.sid] for item in selected)
    )
    false_positives = frozenset().union(
        *(negative_hits[item.sid] for item in selected)
    )
    return CoverageAnalysis(
        positive_samples=positives,
        negative_samples=negatives,
        nodes=nodes,
        relations=relations,
        recommended_sids=tuple(sorted(selected_sids)),
        recommendations=tuple(recommendations),
        covered_positive_samples=tuple(sorted(covered)),
        uncovered_positive_samples=tuple(sorted(set(positives) - covered)),
        false_positive_samples=tuple(sorted(false_positives)),
        optimization_method=method,
    )


def _rule_logic_text(rule: RuleIR) -> str:
    """生成排除 SID/msg/rev/metadata 等管理字段的稳定检测逻辑文本。"""
    features = []
    for feature in rule.features:
        features.append(
            {
                "buffer": feature.buffer,
                "kind": feature.kind,
                "value": feature.value,
                "nocase": feature.nocase,
                "negated": feature.negated,
            }
        )
    value = {
        "action": rule.action,
        "protocol": rule.protocol,
        "header": re.sub(r"\s+", " ", rule.header).strip().casefold(),
        "direction": rule.direction,
        "method": rule.method,
        "features": features,
        "flow": sorted(rule.flow),
        "other_options": list(rule.other_options),
    }
    return json.dumps(
        value,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def rule_profiles_from_ir(rules: Sequence[RuleIR]) -> tuple[RuleProfile, ...]:
    """把 Rule IR 转成 Coverage Graph profile。"""
    profiles: list[RuleProfile] = []
    for rule in rules:
        pcre_count = sum(feature.kind == "pcre" for feature in rule.features)
        content_count = sum(feature.kind == "content" for feature in rule.features)
        content_bytes = sum(
            len(feature.content or b"")
            for feature in rule.features
            if feature.kind == "content"
        )
        sticky_buffers = len({feature.buffer for feature in rule.features})
        # PCRE 的权重与候选编译器保持同一数量级，便于跨来源比较。
        complexity = (
            content_count
            + pcre_count * 5
            + sticky_buffers
            + content_bytes // 16
            + (1 if rule.method else 0)
        )
        profiles.append(
            RuleProfile(
                sid=rule.sid,
                evidence_fingerprint=evidence_fingerprint_id(rule),
                logic_fingerprint=rule_logic_fingerprint_id(rule),
                normalized_text=_rule_logic_text(rule),
                complexity=complexity,
                direction=rule.direction,
                detection_scope=rule.detection_scope,
                pcre_count=pcre_count,
            )
        )
    return tuple(profiles)


def analyze_rule_coverage(
    rules: str | Sequence[RuleIR],
    sample_results: Sequence[object],
    *,
    exact_limit: int = 16,
    evaluated_sids: Sequence[int] | None = None,
) -> CoverageAnalysis:
    """从 .rules 文本或 Rule IR 直接构建 Coverage Graph。"""
    parsed = parse_suricata_rules(rules) if isinstance(rules, str) else tuple(rules)
    return analyze_coverage(
        rule_profiles_from_ir(parsed),
        sample_results,
        exact_limit=exact_limit,
        evaluated_sids=evaluated_sids,
    )


__all__ = [
    "CoverageAnalysis",
    "CoverageNode",
    "CoverageRelation",
    "RuleProfile",
    "RuleRecommendation",
    "analyze_coverage",
    "analyze_rule_coverage",
    "rule_profiles_from_ir",
]
