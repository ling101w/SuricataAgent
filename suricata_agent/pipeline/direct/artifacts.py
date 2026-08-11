"""Atomic artifact writers and result summaries for the direct workflow."""

from __future__ import annotations

import difflib
import hashlib
import json
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from traffic_cases import TrafficSample
from validate_rules import RuleValidationResult


def atomic_text(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(value, encoding="utf-8")
    temporary.replace(path)


def atomic_bytes(path: Path, value: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_bytes(value)
    temporary.replace(path)


def write_json(path: Path, value: object) -> None:
    atomic_text(path, json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n")


def rule_sha256(rule: str) -> str:
    return hashlib.sha256(rule.strip().encode()).hexdigest()


def rule_diff(previous: str, current: str) -> str:
    if not previous or previous == current:
        return ""
    return "\n".join(difflib.unified_diff(
        previous.replace("; ", ";\n").splitlines(),
        current.replace("; ", ";\n").splitlines(),
        fromfile="before.rules", tofile="after.rules", lineterm="",
    ))


def sample_summary(sample: TrafficSample, split: str) -> dict[str, object]:
    value = sample.public_dict()
    value["split"] = split
    return value


def explain_result(validation: RuleValidationResult | None, *, repair_attempts: int, heldout_names: Sequence[str]) -> dict[str, Any]:
    if not validation:
        return {"verdict": "not_verified", "headline": "验证没有完成", "summary": "没有足够的运行证据判断规则是否可以交付。", "checks": [], "failed_samples": [], "limitations": ["不要部署未完成验证的规则。"]}
    sample_results = [item for item in validation.get("sample_results", []) if isinstance(item, dict)]
    failed = [{"name": item.get("name"), "expected": item.get("expected"), "reason": item.get("reason"), "matched_sids": item.get("matched_sids", [])} for item in sample_results if item.get("applicable", True) and not item.get("passed")]
    heldout = [item for item in sample_results if item.get("name") in heldout_names]
    heldout_passed = sum(bool(item.get("passed")) for item in heldout)
    passed = bool(validation.get("passed"))
    checks = [
        {"label": "Suricata syntax", "passed": validation.get("syntax_ok") is True},
        {"label": "Attack traffic", "passed": validation.get("positive_match_ok") is True},
        {"label": "Near-miss traffic", "passed": validation.get("negative_match_ok") is not False},
        {"label": "Held-out verification", "passed": bool(heldout) and heldout_passed == len(heldout), "detail": f"{heldout_passed}/{len(heldout)}" if heldout else "0/0"},
    ]
    if passed:
        headline = "规则已通过运行时验证"
        summary = f"Suricata 成功加载规则，完整样本矩阵全部通过；执行了 {repair_attempts} 次 repair。"
    else:
        headline = "规则未达到交付门槛"
        summary = f"最终验证仍有 {len(failed)} 个适用样本失败；Verify 结果不会回流到 repair。"
    return {"verdict": "verified" if passed else "rejected", "headline": headline, "summary": summary, "checks": checks, "failed_samples": failed, "repair_attempts": repair_attempts, "positive_coverage": validation.get("positive_coverage"), "false_positive_count": validation.get("false_positive_count"), "limitations": ["该结论只覆盖本次 PCAP 矩阵，不代表生产流量零误报。", "新增协议表示或应用版本后应重新回放验证。"]}


__all__ = ["atomic_bytes", "atomic_text", "explain_result", "rule_diff", "rule_sha256", "sample_summary", "write_json"]
