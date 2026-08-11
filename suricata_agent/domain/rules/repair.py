"""Deterministic constraints and acceptance gates for LLM-proposed rule repairs."""

from __future__ import annotations

import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from rule_ir import RuleIRParseError, parse_suricata_rule


@dataclass(frozen=True, slots=True)
class RepairConstraints:
    action: str | None
    protocol: str | None
    header: str | None
    direction: str | None
    sid: int | None
    rev: int | None
    required_flow_options: frozenset[str]
    method: str | None
    required_endpoint_anchors: frozenset[str]
    required_parameter_anchors: frozenset[str]
    source_parse_error: str | None = None

    @classmethod
    def from_rule(cls, rule: str) -> "RepairConstraints":
        try:
            parsed = parse_suricata_rule(rule)
        except (RuleIRParseError, TypeError, ValueError) as exc:
            identity = _fallback_identity(rule)
            return cls(
                **identity,
                method=None,
                required_endpoint_anchors=frozenset(),
                required_parameter_anchors=frozenset(),
                source_parse_error=str(exc)[:500],
            )
        return cls(
            action=parsed.action,
            protocol=parsed.protocol,
            header=_canonical_header(parsed.header),
            direction=parsed.direction,
            sid=parsed.sid,
            rev=parsed.rev,
            required_flow_options=frozenset(parsed.flow),
            method=parsed.method,
            required_endpoint_anchors=frozenset(parsed.evidence.endpoint),
            required_parameter_anchors=frozenset(parsed.evidence.parameter),
        )

    def public_dict(self) -> dict[str, object]:
        return {
            "immutable_action": self.action,
            "immutable_protocol": self.protocol,
            "immutable_header": self.header,
            "immutable_direction": self.direction,
            "immutable_sid": self.sid,
            "immutable_rev": self.rev,
            "required_flow_options": sorted(self.required_flow_options),
            "immutable_method": self.method,
            "required_endpoint_anchors": sorted(self.required_endpoint_anchors),
            "required_parameter_anchors": sorted(self.required_parameter_anchors),
            "source_parse_error": self.source_parse_error,
        }


@dataclass(frozen=True, slots=True)
class RepairAcceptance:
    accepted: bool
    reasons: tuple[str, ...]
    metrics: dict[str, object]


def compare_repair(
    constraints: RepairConstraints,
    candidate_rule: str,
) -> tuple[str, ...]:
    """Return invariant violations introduced by a proposed repair."""
    try:
        candidate = parse_suricata_rule(candidate_rule)
    except (RuleIRParseError, TypeError, ValueError) as exc:
        return (f"修复规则无法解析为 Rule IR：{str(exc)[:500]}",)

    violations: list[str] = []
    for label, before, after in (
        ("action", constraints.action, candidate.action),
        ("protocol", constraints.protocol, candidate.protocol),
        ("header", constraints.header, _canonical_header(candidate.header)),
        ("direction", constraints.direction, candidate.direction),
        ("SID", constraints.sid, candidate.sid),
        ("rev", constraints.rev, candidate.rev),
        ("HTTP method", constraints.method, candidate.method),
    ):
        if before is not None and before != after:
            violations.append(f"不可变字段 {label} 被修改：{before!r} -> {after!r}")

    missing_flow = constraints.required_flow_options - set(candidate.flow)
    if missing_flow:
        violations.append("移除了必需 flow 约束：" + ", ".join(sorted(missing_flow)))

    missing_endpoints = {
        anchor
        for anchor in constraints.required_endpoint_anchors
        if not _anchor_preserved(anchor, candidate.evidence.endpoint, candidate.features)
    }
    if missing_endpoints:
        violations.append("移除了端点语义锚点：" + ", ".join(sorted(missing_endpoints)))

    missing_parameters = {
        anchor
        for anchor in constraints.required_parameter_anchors
        if not _anchor_preserved(anchor, candidate.evidence.parameter, candidate.features)
    }
    if missing_parameters:
        violations.append("移除了参数语义锚点：" + ", ".join(sorted(missing_parameters)))
    return tuple(violations)


def accept_repair(
    before: Mapping[str, Any],
    after: Mapping[str, Any],
) -> RepairAcceptance:
    """Apply a lexicographic no-regression gate to runtime repair results."""
    before_rows = _applicable_rows(before)
    after_rows = _applicable_rows(after)
    before_passed = {name for name, row in before_rows.items() if row.get("passed")}
    after_passed = {name for name, row in after_rows.items() if row.get("passed")}
    regressed = sorted(before_passed - after_passed)

    before_tp = _passed_count(before_rows.values(), "alert")
    after_tp = _passed_count(after_rows.values(), "alert")
    before_fp = _false_positive_count(before, before_rows.values())
    after_fp = _false_positive_count(after, after_rows.values())
    syntax_improved = before.get("syntax_ok") is not True and after.get("syntax_ok") is True

    reasons: list[str] = []
    if after.get("syntax_ok") is not True:
        reasons.append("修复规则未通过 Suricata 语法验证")
    if regressed:
        reasons.append("已通过样本发生回退：" + ", ".join(regressed))
    if after_fp > before_fp:
        reasons.append(f"repair 集误报增加：{before_fp} -> {after_fp}")

    improved = (
        bool(after.get("passed")) and not bool(before.get("passed"))
    ) or after_tp > before_tp or after_fp < before_fp or syntax_improved
    if not improved:
        reasons.append("候选规则没有带来可测的检出、误报或语法改进")

    metrics: dict[str, object] = {
        "syntax_improved": syntax_improved,
        "before_true_positives": before_tp,
        "after_true_positives": after_tp,
        "before_false_positives": before_fp,
        "after_false_positives": after_fp,
        "regressed_samples": regressed,
    }
    return RepairAcceptance(not reasons, tuple(reasons), metrics)


def _fallback_identity(rule: str) -> dict[str, object]:
    header = _canonical_header(rule.split("(", 1)[0]) or None
    tokens = header.split() if header else []
    action = tokens[0].casefold() if len(tokens) >= 1 else None
    protocol = tokens[1].casefold() if len(tokens) >= 2 else None
    sid_match = re.search(r"(?:\(|;)\s*sid\s*:\s*(\d+)\s*(?:;|$)", rule, re.I)
    rev_match = re.search(r"(?:\(|;)\s*rev\s*:\s*(\d+)\s*(?:;|$)", rule, re.I)
    flow_match = re.search(r"(?:\(|;)\s*flow\s*:\s*([^;]+)", rule, re.I)
    flow_options = frozenset(
        item.strip().casefold()
        for item in (flow_match.group(1).split(",") if flow_match else [])
        if item.strip()
    )
    direction = (
        "request"
        if "to_server" in flow_options
        else "response" if "to_client" in flow_options else None
    )
    return {
        "action": action,
        "protocol": protocol,
        "header": header,
        "direction": direction,
        "sid": int(sid_match.group(1)) if sid_match else None,
        "rev": int(rev_match.group(1)) if rev_match else None,
        "required_flow_options": flow_options,
    }


def _canonical_header(value: str) -> str:
    return " ".join(value.strip().split())


def _anchor_preserved(
    anchor: str,
    classified: Sequence[str],
    features: Sequence[object],
) -> bool:
    if anchor in classified:
        return True
    for feature in features:
        value = getattr(feature, "value", "")
        if not isinstance(value, str):
            continue
        normalized = re.sub(r"\\([/._?=&-])", r"\1", value)
        if anchor in normalized:
            return True
    return False


def _applicable_rows(value: Mapping[str, Any]) -> dict[str, Mapping[str, Any]]:
    rows: dict[str, Mapping[str, Any]] = {}
    for row in value.get("sample_results", []):
        if not isinstance(row, Mapping) or row.get("applicable", True) is False:
            continue
        name = row.get("name")
        if isinstance(name, str):
            rows[name] = row
    return rows


def _passed_count(rows: Sequence[Mapping[str, Any]], expected: str) -> int:
    return sum(row.get("expected") == expected and bool(row.get("passed")) for row in rows)


def _false_positive_count(
    validation: Mapping[str, Any],
    rows: Sequence[Mapping[str, Any]],
) -> int:
    explicit = validation.get("false_positive_count")
    if isinstance(explicit, int):
        return explicit
    return sum(
        row.get("expected") == "no_alert" and not bool(row.get("passed"))
        for row in rows
    )


__all__ = [
    "RepairAcceptance",
    "RepairConstraints",
    "accept_repair",
    "compare_repair",
]
