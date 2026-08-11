"""为结构化检测候选计算稳定的证据指纹。"""

from __future__ import annotations

import hashlib
import json
import re
import unicodedata
from collections.abc import Iterable, Sequence
from typing import Protocol, TypeAlias
from urllib.parse import unquote

from rule_knowledge import is_structural_match


EvidenceAtom: TypeAlias = tuple[str, str]
EvidenceFingerprint: TypeAlias = dict[str, object]


class FeatureLike(Protocol):
    """指纹计算所需的最小特征接口。"""

    buffer: str
    content: str | bytes | None
    pcre: str | None


class CandidateLike(Protocol):
    """指纹计算所需的最小候选接口。"""

    direction: str
    features: Sequence[FeatureLike]


class RuleLike(CandidateLike, Protocol):
    """完整规则逻辑指纹所需的最小接口。"""

    action: str
    protocol: str
    method: str | None
    header: str
    flow: Sequence[str]
    other_options: Sequence[str]


_BUFFER_FAMILIES = {
    "file_data": "http.response_body",
    "http.host.raw": "http.host",
    "http.request_header.raw": "http.request_header",
    "http.response_header.raw": "http.response_header",
    "http.uri.raw": "http.uri",
}
_REGEX_META = frozenset(".^$*+?{}[]()|")
_HEX_ESCAPE_RE = re.compile(r"^[0-9A-Fa-f]{2}$")


def _canonical_buffer(buffer: str, direction: str) -> str:
    """将 raw/normalized 等同源 sticky buffer 归并到同一证据位置。"""
    canonical = _BUFFER_FAMILIES.get(buffer, buffer)
    if canonical in {"http.header", "http.header.raw"}:
        return (
            "http.request_header"
            if direction == "request"
            else "http.response_header"
        )
    return canonical


def _split_pcre(expression: str) -> tuple[str, str] | None:
    """宽容拆分 PCRE；语法合法性仍由规则编译器负责。"""
    if not expression.startswith("/"):
        return None
    for index in range(len(expression) - 1, 0, -1):
        if expression[index] != "/":
            continue
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and expression[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            return expression[1:index], expression[index + 1 :]
    return None


def _literal_pcre(pattern: str) -> str | None:
    """仅在 PCRE 确定为字面量时还原，避免把真实正则误判为 content。"""
    result: list[str] = []
    index = 0
    while index < len(pattern):
        char = pattern[index]
        if char in _REGEX_META:
            return None
        if char != "\\":
            result.append(char)
            index += 1
            continue
        if index + 1 >= len(pattern):
            return None
        escaped = pattern[index + 1]
        if escaped == "x" and index + 3 < len(pattern):
            digits = pattern[index + 2 : index + 4]
            if _HEX_ESCAPE_RE.fullmatch(digits):
                result.append(chr(int(digits, 16)))
                index += 4
                continue
        if escaped in _REGEX_META or escaped in {"/", "\\", "-", " ", ":", ";"}:
            result.append(escaped)
            index += 2
            continue
        return None
    return "".join(result)


def _canonical_text(value: str | bytes, buffer: str) -> str:
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            value = "".join(f"\\x{byte:02x}" for byte in value)
    normalized = unicodedata.normalize("NFKC", value).strip().casefold()
    if buffer == "http.uri":
        # 双重编码在漏洞请求中常见，有限次数解码可避免表示差异伪装成新证据。
        for _ in range(2):
            decoded = unquote(normalized)
            if decoded == normalized:
                break
            normalized = decoded
        normalized = normalized.replace("\\", "/")
    return normalized


def _feature_atom(feature: FeatureLike, direction: str) -> EvidenceAtom:
    buffer = _canonical_buffer(feature.buffer, direction)
    polarity = "not-" if bool(getattr(feature, "negated", False)) else ""
    if feature.content is not None:
        return (
            buffer,
            polarity + "literal:" + _canonical_text(feature.content, buffer),
        )

    expression = feature.pcre or ""
    parsed = _split_pcre(expression)
    if parsed is not None:
        pattern, _modifiers = parsed
        literal = _literal_pcre(pattern)
        if literal is not None:
            return buffer, "literal:" + _canonical_text(literal, buffer)
        expression = pattern
    normalized = unicodedata.normalize("NFKC", expression).strip().casefold()
    return buffer, polarity + "regex:" + normalized


def _pcre_marker_text(expression: str) -> str:
    """还原常见 PCRE 转义，供攻击语义标记判断使用。"""
    parsed = _split_pcre(expression)
    pattern = parsed[0] if parsed is not None else expression
    pattern = re.sub(r"\\s(?:[+*?]|\{\d+(?:,\d*)?\})?", " ", pattern)
    return re.sub(r"\\([.\\/^$*+?{}\[\]()|;:\-])", r"\1", pattern)


def _is_exploit_feature(feature: FeatureLike, direction: str) -> bool:
    if bool(getattr(feature, "negated", False)):
        return False
    buffer, normalized = _feature_atom(feature, direction)
    kind, value = normalized.split(":", 1)
    if kind == "regex" and feature.pcre is not None:
        value = _pcre_marker_text(feature.pcre)
    match_kind = "content" if kind == "literal" else "pcre"
    return not is_structural_match(buffer, value, kind=match_kind)


def _logic_content(value: str | bytes, nocase: bool) -> str:
    raw = value if isinstance(value, bytes) else value.encode("utf-8")
    if nocase:
        raw = raw.lower()
    return raw.hex().upper()


def rule_logic_fingerprint(rule: RuleLike) -> EvidenceFingerprint:
    """计算包含方向、限定符、极性和 PCRE modifier 的完整规则逻辑指纹。"""
    features: list[dict[str, object]] = []
    for feature in rule.features:
        nocase = bool(getattr(feature, "nocase", False))
        negated = bool(getattr(feature, "negated", False))
        if feature.content is not None:
            features.append(
                {
                    "buffer": feature.buffer.casefold(),
                    "kind": "content",
                    "content_hex": _logic_content(feature.content, nocase),
                    "nocase": nocase,
                    "negated": negated,
                }
            )
            continue

        expression = feature.pcre or ""
        parsed = _split_pcre(expression)
        pattern, modifiers = parsed if parsed is not None else (expression, "")
        features.append(
            {
                "buffer": feature.buffer.casefold(),
                "kind": "pcre",
                "pattern": unicodedata.normalize("NFKC", pattern),
                "modifiers": "".join(sorted(modifiers)),
                "negated": negated,
            }
        )

    return {
        "version": 1,
        "action": rule.action.casefold(),
        "protocol": rule.protocol.casefold(),
        "header": re.sub(r"\s+", " ", rule.header).strip().casefold(),
        "direction": rule.direction,
        "method": rule.method.upper() if rule.method is not None else None,
        "flow": sorted(value.casefold() for value in rule.flow),
        "features": features,
        "other_options": [
            re.sub(r"\s+", " ", value).strip()
            for value in rule.other_options
        ],
    }


def rule_logic_fingerprint_id(rule: RuleLike) -> str:
    """返回完整规则逻辑的稳定索引标识。"""
    canonical = json.dumps(
        rule_logic_fingerprint(rule),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "lfp:v1:" + hashlib.sha256(canonical).hexdigest()


def candidate_evidence_set(
    candidate: CandidateLike,
    *,
    exploit_only: bool = False,
) -> frozenset[EvidenceAtom]:
    """返回候选的可比较证据集合，可选择只保留利用语义证据。"""
    return frozenset(
        _feature_atom(feature, candidate.direction)
        for feature in candidate.features
        if not exploit_only or _is_exploit_feature(feature, candidate.direction)
    )


def evidence_set(
    candidate: CandidateLike,
    *,
    exploit_only: bool = False,
) -> frozenset[EvidenceAtom]:
    """candidate_evidence_set 的简洁公开别名。"""
    return candidate_evidence_set(candidate, exploit_only=exploit_only)


def novel_evidence(
    candidate: CandidateLike,
    baselines: Iterable[CandidateLike],
    *,
    exploit_only: bool = False,
) -> frozenset[EvidenceAtom]:
    """返回 candidate 相对一组基线候选新增的证据。"""
    baseline_evidence: set[EvidenceAtom] = set()
    for baseline in baselines:
        baseline_evidence.update(
            candidate_evidence_set(baseline, exploit_only=exploit_only)
        )
    return candidate_evidence_set(candidate, exploit_only=exploit_only).difference(
        baseline_evidence
    )


def evidence_fingerprint(candidate: CandidateLike) -> EvidenceFingerprint:
    """返回顺序稳定且可直接 JSON 序列化的候选证据指纹。"""
    evidence = sorted(candidate_evidence_set(candidate))
    return {
        "version": 1,
        "direction": candidate.direction,
        "evidence": [
            {"buffer": buffer, "value": value}
            for buffer, value in evidence
        ],
    }


def evidence_fingerprint_id(candidate: CandidateLike) -> str:
    """返回可用于索引、聚类和 Coverage Graph 的稳定短标识。"""
    canonical = json.dumps(
        evidence_fingerprint(candidate),
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return "efp:v1:" + hashlib.sha256(canonical).hexdigest()


__all__ = [
    "CandidateLike",
    "EvidenceAtom",
    "EvidenceFingerprint",
    "FeatureLike",
    "RuleLike",
    "candidate_evidence_set",
    "evidence_set",
    "evidence_fingerprint",
    "evidence_fingerprint_id",
    "novel_evidence",
    "rule_logic_fingerprint",
    "rule_logic_fingerprint_id",
]
