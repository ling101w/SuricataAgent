"""将 LLM 提取的结构化检测特征确定性编译为 Suricata 规则。"""

from __future__ import annotations

import json
import re
from dataclasses import asdict, dataclass, field
from typing import Any, Literal, Mapping, Sequence

from evidence_fingerprint import (
    candidate_evidence_set,
    evidence_fingerprint,
    novel_evidence,
)
from rule_knowledge import (
    CANDIDATE_ROLES,
    DYNAMIC_BUFFER_FIELDS,
    DYNAMIC_HTTP_FIELDS,
    HEADER_BUFFERS,
    REQUIRED_CANDIDATE_COUNT,
    RESPONSE_BUFFERS,
    SUPPORTED_BUFFERS,
    CandidateRole,
    DetectionScope,
    Direction,
    candidate_count_is_valid,
    candidate_detection_scope,
    candidate_roles_are_valid,
    contains_exploit_marker,
    is_buffer_allowed,
    is_endpoint_match,
    is_structural_match,
    looks_like_windows_path,
)


MAX_FEATURES = 32
MAX_CONTENT_BYTES = 4_096
MAX_PCRE_CHARS = 4_096
MAX_REASON_CHARS = 4_000
MIN_CONTENT_BYTES = 4

_CANDIDATE_FIELDS = {
    "role",
    "detection_scope",
    "direction",
    "protocol",
    "method",
    "features",
    "dynamic_fields",
    "reason",
}
_FEATURE_FIELDS = {"buffer", "content", "pcre", "nocase"}

_DYNAMIC_HEADER_RE = re.compile(
    r"^\s*(?:"
    + "|".join(re.escape(name) for name in DYNAMIC_HTTP_FIELDS)
    + r")\s*:?(?:\s|$)",
    re.IGNORECASE,
)
_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$")
_CLASSTYPE_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")
# PCRE 通用修饰符以及 Suricata 仍兼容的 HTTP/相对匹配修饰符。
_PCRE_MODIFIERS = frozenset("imsxAEGOBRUIPQHDMCSYVWZ")
_RESPONSE_BODY_BUFFERS = frozenset({"file_data", "http.response_body"})
_GENERIC_RESPONSE_VALUES = frozenset(
    {
        "ok",
        "success",
        "successful",
        "error",
        "failed",
        "failure",
        "exception",
        "not found",
        "internal server error",
    }
)
_PASSWD_RECORD_RE = re.compile(
    r"(?m)^[A-Za-z_][A-Za-z0-9_-]*:[^:\r\n]*:[0-9]+:[0-9]+:[^:\r\n]*:/[^:\r\n]*:/[^\r\n]+$"
)
_INI_SECTION_RE = re.compile(
    r"(?i)^\[(?:fonts|extensions|mci extensions|files|mail)\]$"
)


class DetectionSchemaError(ValueError):
    """模型输出不符合结构化检测特征 schema。"""

    def __init__(self, path: str, message: str) -> None:
        self.path = path
        self.detail = message
        super().__init__(f"{path}：{message}")


@dataclass(frozen=True)
class LintIssue:
    """一项会导致规则过宽、无效或方向错误的质量问题。"""

    code: str
    message: str
    feature_index: int | None = None


class RuleLintError(ValueError):
    """候选特征未通过确定性规则质量检查。"""

    def __init__(self, issues: Sequence[LintIssue]) -> None:
        self.issues = tuple(issues)
        detail = "；".join(issue.message for issue in self.issues)
        super().__init__(f"候选规则未通过质量检查：{detail}")


@dataclass(frozen=True)
class DetectionFeature:
    """一个限定在 HTTP sticky buffer 内的匹配特征。"""

    buffer: str
    content: str | None = None
    pcre: str | None = None
    nocase: bool = False

    @property
    def kind(self) -> Literal["content", "pcre"]:
        return "content" if self.content is not None else "pcre"


@dataclass(frozen=True)
class DetectionCandidate:
    """LLM 只负责选择特征，不包含任何 Suricata 管理字段。"""

    role: CandidateRole
    direction: Direction
    protocol: Literal["http"]
    method: str | None
    features: tuple[DetectionFeature, ...]
    dynamic_fields: tuple[str, ...]
    reason: str
    detection_scope: DetectionScope = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(
            self,
            "detection_scope",
            candidate_detection_scope(self.role, self.direction),
        )


@dataclass(frozen=True)
class DetectionPlan:
    """包含按固定角色顺序排列的三个独立候选方案。"""

    candidates: tuple[DetectionCandidate, ...]


@dataclass(frozen=True)
class ComplexityMetadata:
    """用于候选排序的轻量复杂度数据，不代表运行时精确开销。"""

    content_count: int
    pcre_count: int
    sticky_buffer_count: int
    dynamic_field_count: int
    nocase_count: int
    content_bytes: int
    estimated_cost: int


@dataclass(frozen=True)
class CompiledRule:
    """单个候选的规则文本及其可比较元数据。"""

    candidate_index: int
    role: CandidateRole
    sid: int
    rule: str
    complexity: ComplexityMetadata

    def to_dict(self) -> dict[str, Any]:
        return {
            "candidate_index": self.candidate_index,
            "role": self.role,
            "sid": self.sid,
            "rule": self.rule,
            "complexity": asdict(self.complexity),
        }


@dataclass(frozen=True)
class CompilationResult:
    """一次批量编译的结果。"""

    candidates: tuple[CompiledRule, ...]

    @property
    def rules(self) -> str:
        return "\n".join(item.rule for item in self.candidates)

    @property
    def complexity(self) -> tuple[ComplexityMetadata, ...]:
        return tuple(item.complexity for item in self.candidates)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rules": self.rules,
            "candidates": [item.to_dict() for item in self.candidates],
        }


class _DuplicateKeyError(ValueError):
    pass


def _object_without_duplicate_keys(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateKeyError(f"JSON 对象包含重复字段 {key!r}")
        result[key] = value
    return result


def _reject_json_constant(value: str) -> None:
    raise ValueError(f"JSON 不允许使用非常量数值 {value}")


def _require_object(value: object, path: str) -> dict[str, Any]:
    if type(value) is not dict:
        raise DetectionSchemaError(path, "必须是 JSON 对象")
    return value


def _require_exact_fields(
    value: Mapping[str, Any],
    required: set[str],
    allowed: set[str],
    path: str,
) -> None:
    missing = sorted(required - value.keys())
    unknown = sorted(value.keys() - allowed)
    if missing:
        raise DetectionSchemaError(path, f"缺少字段：{', '.join(missing)}")
    if unknown:
        raise DetectionSchemaError(path, f"包含未知字段：{', '.join(unknown)}")


def _parse_feature(value: object, path: str) -> DetectionFeature:
    data = _require_object(value, path)
    _require_exact_fields(data, {"buffer"}, _FEATURE_FIELDS, path)

    has_content = "content" in data
    has_pcre = "pcre" in data
    if has_content == has_pcre:
        raise DetectionSchemaError(path, "必须且只能提供 content 或 pcre 之一")

    buffer = data["buffer"]
    if type(buffer) is not str or buffer not in SUPPORTED_BUFFERS:
        supported = "、".join(sorted(SUPPORTED_BUFFERS))
        raise DetectionSchemaError(
            f"{path}.buffer",
            f"不支持的 sticky buffer；允许值：{supported}",
        )

    nocase = data.get("nocase", False)
    if type(nocase) is not bool:
        raise DetectionSchemaError(f"{path}.nocase", "必须是布尔值")

    if has_content:
        content = data["content"]
        if type(content) is not str or not content:
            raise DetectionSchemaError(f"{path}.content", "必须是非空字符串")
        content_size = len(content.encode("utf-8"))
        if content_size > MAX_CONTENT_BYTES:
            raise DetectionSchemaError(
                f"{path}.content",
                f"UTF-8 编码后不能超过 {MAX_CONTENT_BYTES} 字节",
            )
        return DetectionFeature(buffer=buffer, content=content, nocase=nocase)

    pcre = data["pcre"]
    if type(pcre) is not str or not pcre:
        raise DetectionSchemaError(f"{path}.pcre", "必须是非空字符串")
    if len(pcre) > MAX_PCRE_CHARS:
        raise DetectionSchemaError(
            f"{path}.pcre", f"不能超过 {MAX_PCRE_CHARS} 个字符"
        )
    if "nocase" in data:
        raise DetectionSchemaError(
            f"{path}.nocase", "PCRE 的大小写选项必须写在表达式修饰符中"
        )
    return DetectionFeature(buffer=buffer, pcre=pcre)


def _unanchored_pcre_indexes(
    features: Sequence[DetectionFeature],
) -> tuple[int, ...]:
    """返回没有同一连续 sticky buffer content 前缀的 PCRE 下标。"""
    indexes: list[int] = []
    active_buffer: str | None = None
    active_buffer_has_content = False
    for index, feature in enumerate(features):
        if feature.buffer != active_buffer:
            active_buffer = feature.buffer
            active_buffer_has_content = False
        if feature.content is not None:
            active_buffer_has_content = True
        elif not active_buffer_has_content:
            indexes.append(index)
    return tuple(indexes)


def _parse_candidate(value: object, path: str) -> DetectionCandidate:
    data = _require_object(value, path)
    _require_exact_fields(data, _CANDIDATE_FIELDS, _CANDIDATE_FIELDS, path)

    role = data["role"]
    if type(role) is not str or role not in CANDIDATE_ROLES:
        raise DetectionSchemaError(
            f"{path}.role",
            f"只允许 {'、'.join(CANDIDATE_ROLES)}",
        )

    direction = data["direction"]
    if direction not in ("request", "response"):
        raise DetectionSchemaError(
            f"{path}.direction", "只允许 request 或 response"
        )

    detection_scope = data["detection_scope"]
    expected_scope = candidate_detection_scope(role, direction)
    if detection_scope != expected_scope:
        raise DetectionSchemaError(
            f"{path}.detection_scope",
            f"{role}/{direction} 候选必须是 {expected_scope}",
        )

    protocol = data["protocol"]
    if protocol != "http":
        raise DetectionSchemaError(
            f"{path}.protocol", "当前编译器只支持 http"
        )

    method = data["method"]
    if method is not None:
        if type(method) is not str or not method.strip():
            raise DetectionSchemaError(
                f"{path}.method", "必须是 HTTP 方法字符串或 null"
            )
        method = method.strip().upper()
        if not _METHOD_RE.fullmatch(method):
            raise DetectionSchemaError(
                f"{path}.method", "包含非法的 HTTP method 字符"
            )

    feature_values = data["features"]
    if type(feature_values) is not list:
        raise DetectionSchemaError(f"{path}.features", "必须是数组")
    if not 1 <= len(feature_values) <= MAX_FEATURES:
        raise DetectionSchemaError(
            f"{path}.features", f"数量必须在 1 到 {MAX_FEATURES} 之间"
        )
    features = tuple(
        _parse_feature(item, f"{path}.features[{index}]")
        for index, item in enumerate(feature_values)
    )
    unanchored_pcre = _unanchored_pcre_indexes(features)
    if unanchored_pcre:
        index = unanchored_pcre[0]
        raise DetectionSchemaError(
            f"{path}.features[{index}].pcre",
            "前面必须有同一连续 sticky buffer 中的 content 锚点",
        )

    dynamic_values = data["dynamic_fields"]
    if type(dynamic_values) is not list:
        raise DetectionSchemaError(f"{path}.dynamic_fields", "必须是字符串数组")
    if len(dynamic_values) > MAX_FEATURES:
        raise DetectionSchemaError(
            f"{path}.dynamic_fields", f"数量不能超过 {MAX_FEATURES}"
        )
    dynamic_fields: list[str] = []
    seen_dynamic_fields: set[str] = set()
    for index, item in enumerate(dynamic_values):
        item_path = f"{path}.dynamic_fields[{index}]"
        if type(item) is not str or not item.strip():
            raise DetectionSchemaError(item_path, "必须是非空字符串")
        field_name = item.strip().rstrip(":")
        if len(field_name) > 128:
            raise DetectionSchemaError(item_path, "不能超过 128 个字符")
        normalized_name = field_name.casefold()
        if normalized_name in seen_dynamic_fields:
            raise DetectionSchemaError(item_path, f"动态字段 {field_name!r} 重复")
        seen_dynamic_fields.add(normalized_name)
        dynamic_fields.append(field_name)

    reason = data["reason"]
    if type(reason) is not str or not reason.strip():
        raise DetectionSchemaError(f"{path}.reason", "必须是非空字符串")
    reason = reason.strip()
    if len(reason) > MAX_REASON_CHARS:
        raise DetectionSchemaError(
            f"{path}.reason", f"不能超过 {MAX_REASON_CHARS} 个字符"
        )

    return DetectionCandidate(
        role=role,
        direction=direction,
        protocol=protocol,
        method=method,
        features=features,
        dynamic_fields=tuple(dynamic_fields),
        reason=reason,
    )


def _candidate_diversity_error(
    candidates: Sequence[DetectionCandidate],
) -> str | None:
    """检查角色标签背后的证据组合是否真的不同。"""
    fingerprints = [evidence_fingerprint(candidate) for candidate in candidates]
    for left in range(len(fingerprints)):
        for right in range(left + 1, len(fingerprints)):
            if fingerprints[left] == fingerprints[right]:
                return (
                    f"{candidates[left].role} 与 {candidates[right].role} "
                    "使用了相同证据集合；仅修改 raw buffer、大小写、nocase、method、"
                    "reason、动态字段或等价字面量 PCRE 不算独立候选"
                )

    precision, robust, alternative = candidates
    if precision.direction != "request":
        return "precision 候选必须检测 request 中的 endpoint 与利用语义"
    if robust.direction != "request":
        return "robust 候选必须从 request 中选择抗表示变化的利用证据"
    precision_has_endpoint = any(
        feature.content is not None
        and is_endpoint_match(feature.buffer, feature.content)
        for feature in precision.features
    )
    precision_has_exploit = any(
        feature.pcre is not None
        or feature.content is not None
        and not is_structural_match(feature.buffer, feature.content)
        for feature in precision.features
    )
    if not precision_has_endpoint or not precision_has_exploit:
        return "precision 候选必须同时包含 endpoint 锚点和非结构性的利用证据"

    robust_exploit_evidence = candidate_evidence_set(robust, exploit_only=True)
    robust_has_endpoint = any(
        feature.content is not None
        and is_endpoint_match(feature.buffer, feature.content)
        for feature in robust.features
    )
    if not robust_has_endpoint:
        return "robust 候选必须保留最小 endpoint 身份锚点"
    if not robust_exploit_evidence:
        return "robust 候选必须包含非结构性的利用证据"

    if alternative.role == "alternative_evidence" and alternative.direction == "request":
        alternative_exploit_evidence = candidate_evidence_set(
            alternative,
            exploit_only=True,
        )
        if not alternative_exploit_evidence:
            return "alternative_evidence 请求候选必须包含非结构性的利用证据"
        alternative_novel_evidence = novel_evidence(
            alternative,
            candidates[:-1],
            exploit_only=True,
        )
        if not alternative_novel_evidence:
            return (
                "alternative_evidence 请求候选必须包含 precision/robust "
                "尚未使用的独立利用证据"
            )
    if alternative.direction == "response":
        response_features = tuple(
            feature
            for feature in alternative.features
            if feature.buffer in _RESPONSE_BODY_BUFFERS
        )
        if not response_features:
            return "alternative_evidence 响应候选必须包含响应正文成功证据"
        values = tuple(
            (feature.content or feature.pcre or "").strip()
            for feature in response_features
        )
        strong_single = any(
            value.casefold() not in _GENERIC_RESPONSE_VALUES
            and (
                contains_exploit_marker(value)
                or looks_like_windows_path(value)
                or _PASSWD_RECORD_RE.search(value) is not None
                or _INI_SECTION_RE.fullmatch(value) is not None
            )
            for value in values
        )
        independent_values = {
            value.casefold()
            for value in values
            if value and value.casefold() not in _GENERIC_RESPONSE_VALUES
        }
        if not strong_single and len(independent_values) < 2:
            return (
                "alternative_evidence 响应候选必须包含一条可确认的强成功特征，"
                "或至少两条独立响应正文证据；通用状态文本不能作为成功证据"
            )
    return None


def parse_detection_data(value: object) -> DetectionPlan:
    """严格解析已解码的 JSON 数据，未知字段不会被静默忽略。"""
    data = _require_object(value, "$")
    _require_exact_fields(data, {"candidates"}, {"candidates"}, "$")
    values = data["candidates"]
    if type(values) is not list:
        raise DetectionSchemaError("$.candidates", "必须是数组")
    if not candidate_count_is_valid(len(values)):
        raise DetectionSchemaError(
            "$.candidates",
            f"候选数量必须恰好为 {REQUIRED_CANDIDATE_COUNT}",
        )
    candidates = tuple(
        _parse_candidate(item, f"$.candidates[{index}]")
        for index, item in enumerate(values)
    )
    actual_roles = tuple(candidate.role for candidate in candidates)
    if not candidate_roles_are_valid(actual_roles):
        raise DetectionSchemaError(
            "$.candidates",
            "role 必须按顺序且唯一对应 " + "、".join(CANDIDATE_ROLES),
        )
    diversity_error = _candidate_diversity_error(candidates)
    if diversity_error is not None:
        raise DetectionSchemaError("$.candidates", diversity_error)
    return DetectionPlan(candidates=candidates)


def parse_detection_json(payload: str | bytes | bytearray) -> DetectionPlan:
    """严格解析模型 JSON；拒绝代码围栏、重复键、NaN 和未知字段。"""
    if not isinstance(payload, (str, bytes, bytearray)):
        raise DetectionSchemaError("$", "输入必须是 JSON 文本")
    try:
        value = json.loads(
            payload,
            object_pairs_hook=_object_without_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (json.JSONDecodeError, UnicodeDecodeError, _DuplicateKeyError, ValueError) as exc:
        raise DetectionSchemaError("$", f"JSON 解析失败：{exc}") from exc
    return parse_detection_data(value)


def encode_content(value: str) -> str:
    """编码 Suricata content 值；危险字符和不可打印字节使用十六进制块。"""
    if type(value) is not str or not value:
        raise ValueError("content 必须是非空字符串")

    rendered: list[str] = []
    hex_bytes: list[int] = []

    def flush_hex() -> None:
        if not hex_bytes:
            return
        rendered.append("|" + " ".join(f"{byte:02X}" for byte in hex_bytes) + "|")
        hex_bytes.clear()

    for byte in value.encode("utf-8"):
        safe = 0x20 <= byte <= 0x7E and byte not in {0x22, 0x3B, 0x5C, 0x7C}
        if safe:
            flush_hex()
            rendered.append(chr(byte))
        else:
            hex_bytes.append(byte)
    flush_hex()
    return "".join(rendered)


def _pcre_error(expression: str) -> str | None:
    if "\r" in expression or "\n" in expression or "\x00" in expression:
        return "PCRE 不能包含换行或 NUL 字符"
    if '"' in expression or ";" in expression:
        return "PCRE 不能直接包含引号或分号，请改用 \\x22 或 \\x3b"
    if not expression.startswith("/"):
        return "PCRE 必须使用 /pattern/modifiers 格式"

    closing = -1
    for index in range(len(expression) - 1, 0, -1):
        if expression[index] != "/":
            continue
        backslashes = 0
        cursor = index - 1
        while cursor >= 0 and expression[cursor] == "\\":
            backslashes += 1
            cursor -= 1
        if backslashes % 2 == 0:
            closing = index
            break
    if closing <= 1:
        return "PCRE 缺少未转义的结束分隔符或表达式为空"

    modifiers = expression[closing + 1 :]
    if modifiers and re.fullmatch(r"[A-Za-z]+", modifiers) is None:
        return "PCRE 修饰符只能包含英文字母"
    if len(set(modifiers)) != len(modifiers):
        return "PCRE 修饰符不能重复"
    unsupported = sorted(set(modifiers) - _PCRE_MODIFIERS)
    if unsupported:
        return f"PCRE 包含不支持的修饰符：{''.join(unsupported)}"
    return None


def _is_structural_content(feature: DetectionFeature) -> bool:
    assert feature.content is not None
    return is_structural_match(feature.buffer, feature.content)


def lint_candidate(candidate: DetectionCandidate) -> tuple[LintIssue, ...]:
    """检查编译前可确定的方向、sticky buffer 和规则质量问题。"""
    issues: list[LintIssue] = []

    if candidate.direction == "response" and candidate.method is not None:
        issues.append(
            LintIssue(
                "METHOD_ON_RESPONSE",
                "响应方向候选不能同时匹配请求 method",
            )
        )

    content_features: list[DetectionFeature] = []
    pcre_count = 0
    unanchored_pcre = set(_unanchored_pcre_indexes(candidate.features))

    for index, feature in enumerate(candidate.features):
        feature_number = index + 1
        allowed_for_direction = is_buffer_allowed(candidate.direction, feature.buffer)
        if not allowed_for_direction:
            issues.append(
                LintIssue(
                    "BUFFER_DIRECTION_MISMATCH",
                    f"第 {feature_number} 个特征的 {feature.buffer} 与 {candidate.direction} 方向不一致",
                    index,
                )
            )

        if feature.buffer == "http.method":
            issues.append(
                LintIssue(
                    "METHOD_BUFFER_NOT_ALLOWED",
                    f"第 {feature_number} 个特征重复使用 http.method；请使用顶层 method 字段",
                    index,
                )
            )

        dynamic_name = DYNAMIC_BUFFER_FIELDS.get(feature.buffer)
        if dynamic_name is not None:
            issues.append(
                LintIssue(
                    "DYNAMIC_HEADER_MATCH",
                    f"第 {feature_number} 个特征不能匹配动态字段 {dynamic_name}",
                    index,
                )
            )

        if feature.content is not None:
            content_features.append(feature)
            if not feature.content.strip():
                issues.append(
                    LintIssue(
                        "BLANK_CONTENT",
                        f"第 {feature_number} 个 content 不能只包含空白字符",
                        index,
                    )
                )
            if (
                feature.buffer in HEADER_BUFFERS
                and _DYNAMIC_HEADER_RE.match(feature.content)
            ):
                issues.append(
                    LintIssue(
                        "DYNAMIC_HEADER_MATCH",
                        f"第 {feature_number} 个特征不能匹配 Host、Content-Length 或 Cookie",
                        index,
                    )
                )
        else:
            pcre_count += 1
            assert feature.pcre is not None
            error = _pcre_error(feature.pcre)
            if error is not None:
                issues.append(
                    LintIssue(
                        "INVALID_PCRE",
                        f"第 {feature_number} 个特征的 {error}",
                        index,
                    )
                )
            if index in unanchored_pcre:
                issues.append(
                    LintIssue(
                        "UNANCHORED_PCRE",
                        f"第 {feature_number} 个 PCRE 前必须有同一连续 sticky buffer 内的 content 锚点",
                        index,
                    )
                )

    if len(content_features) == 1:
        only_content = content_features[0].content
        assert only_content is not None
        if len(only_content.encode("utf-8")) < MIN_CONTENT_BYTES:
            issues.append(
                LintIssue(
                    "SHORT_SINGLE_CONTENT",
                    f"唯一的 content 少于 {MIN_CONTENT_BYTES} 字节，误报风险过高",
                )
            )

    if content_features and pcre_count == 0 and all(
        _is_structural_content(feature) for feature in content_features
    ):
        issues.append(
            LintIssue(
                "WEAK_STRUCTURAL_ONLY",
                "候选只匹配 URI 路径和参数名，必须增加实际利用值特征",
            )
        )

    return tuple(issues)


def _safe_msg_prefix(value: str) -> str:
    if type(value) is not str:
        raise ValueError("msg_prefix 必须是字符串")
    # msg 是管理字段，不允许模型或调用方把规则分隔符带入最终语法。
    cleaned = re.sub(r"[^A-Za-z0-9 ._:/()\-]", " ", value)
    cleaned = " ".join(cleaned.split())[:120].strip()
    return cleaned or "Generated HTTP detection"


def _validate_compile_fields(
    *, sid: int, rev: int, classtype: str, candidate_index: int
) -> None:
    if type(sid) is not int or not 1 <= sid <= 4_294_967_295:
        raise ValueError("SID 必须是 1 到 4294967295 之间的整数")
    if type(rev) is not int or rev < 1:
        raise ValueError("rev 必须是正整数")
    if type(candidate_index) is not int or candidate_index < 1:
        raise ValueError("candidate_index 必须是正整数")
    if type(classtype) is not str or not _CLASSTYPE_RE.fullmatch(classtype):
        raise ValueError("classtype 只能包含字母、数字、下划线和连字符")


def _complexity(candidate: DetectionCandidate) -> ComplexityMetadata:
    content_features = [
        feature for feature in candidate.features if feature.content is not None
    ]
    pcre_count = sum(feature.pcre is not None for feature in candidate.features)
    method_count = int(candidate.method is not None)
    buffers = {feature.buffer for feature in candidate.features}
    if candidate.method is not None:
        buffers.add("http.method")
    content_bytes = sum(
        len(feature.content.encode("utf-8"))
        for feature in content_features
        if feature.content is not None
    ) + (len(candidate.method) if candidate.method is not None else 0)
    content_count = len(content_features) + method_count
    nocase_count = sum(feature.nocase for feature in content_features)
    dynamic_count = len(candidate.dynamic_fields)
    estimated_cost = (
        content_count
        + len(buffers)
        + nocase_count
        + pcre_count * 5
    )
    return ComplexityMetadata(
        content_count=content_count,
        pcre_count=pcre_count,
        sticky_buffer_count=len(buffers),
        dynamic_field_count=dynamic_count,
        nocase_count=nocase_count,
        content_bytes=content_bytes,
        estimated_cost=estimated_cost,
    )


def compile_candidate(
    candidate: DetectionCandidate,
    *,
    sid: int,
    candidate_index: int = 1,
    msg_prefix: str = "Generated HTTP detection",
    classtype: str = "web-application-attack",
    rev: int = 1,
) -> CompiledRule:
    """将一个已解析候选编译成单行合法规则；管理字段完全由程序生成。"""
    _validate_compile_fields(
        sid=sid,
        rev=rev,
        classtype=classtype,
        candidate_index=candidate_index,
    )
    issues = lint_candidate(candidate)
    if issues:
        raise RuleLintError(issues)

    direction_text = "request" if candidate.direction == "request" else "response"
    msg = (
        f"{_safe_msg_prefix(msg_prefix)} {direction_text} "
        f"{candidate.role} candidate {candidate_index}"
    )
    flow = "established,to_server" if candidate.direction == "request" else "established,to_client"
    options = [f'msg:"{msg}"', f"flow:{flow}"]

    active_buffer: str | None = None
    if candidate.method is not None:
        options.extend(("http.method", f'content:"{encode_content(candidate.method)}"'))
        active_buffer = "http.method"

    for feature in candidate.features:
        if feature.buffer != active_buffer:
            options.append(feature.buffer)
            active_buffer = feature.buffer
        if feature.content is not None:
            options.append(f'content:"{encode_content(feature.content)}"')
            if feature.nocase:
                options.append("nocase")
        else:
            assert feature.pcre is not None
            options.append(f'pcre:"{feature.pcre}"')

    options.extend(
        (
            f"metadata:detection_scope {candidate.detection_scope}",
            f"classtype:{classtype}",
            f"sid:{sid}",
            f"rev:{rev}",
        )
    )
    rule = f"alert {candidate.protocol} any any -> any any (" + "; ".join(options) + ";)"
    return CompiledRule(
        candidate_index=candidate_index,
        role=candidate.role,
        sid=sid,
        rule=rule,
        complexity=_complexity(candidate),
    )


def compile_candidates(
    plan: DetectionPlan | Sequence[DetectionCandidate],
    *,
    sid_start: int = 123,
    msg_prefix: str = "Generated HTTP detection",
    classtype: str = "web-application-attack",
    rev: int = 1,
) -> CompilationResult:
    """按固定角色顺序编译三个候选，并从 sid_start 开始连续分配 SID。"""
    candidates = plan.candidates if isinstance(plan, DetectionPlan) else tuple(plan)
    if not candidate_count_is_valid(len(candidates)):
        raise ValueError(
            f"候选数量必须恰好为 {REQUIRED_CANDIDATE_COUNT}"
        )
    actual_roles = tuple(candidate.role for candidate in candidates)
    if not candidate_roles_are_valid(actual_roles):
        raise ValueError(
            "候选 role 必须按顺序且唯一对应 " + "、".join(CANDIDATE_ROLES)
        )
    diversity_error = _candidate_diversity_error(candidates)
    if diversity_error is not None:
        raise ValueError(diversity_error)
    if type(sid_start) is not int or not 1 <= sid_start <= 4_294_967_295:
        raise ValueError("sid_start 必须是 1 到 4294967295 之间的整数")
    if sid_start + len(candidates) - 1 > 4_294_967_295:
        raise ValueError("连续分配 SID 后超过 Suricata SID 上限")

    return CompilationResult(
        candidates=tuple(
            compile_candidate(
                candidate,
                sid=sid_start + index,
                candidate_index=index + 1,
                msg_prefix=msg_prefix,
                classtype=classtype,
                rev=rev,
            )
            for index, candidate in enumerate(candidates)
        )
    )


def compile_detection_json(
    payload: str | bytes | bytearray,
    *,
    sid_start: int = 123,
    msg_prefix: str = "Generated HTTP detection",
    classtype: str = "web-application-attack",
    rev: int = 1,
) -> CompilationResult:
    """从模型 JSON 到最终规则的一站式确定性入口。"""
    return compile_candidates(
        parse_detection_json(payload),
        sid_start=sid_start,
        msg_prefix=msg_prefix,
        classtype=classtype,
        rev=rev,
    )


__all__ = [
    "CompilationResult",
    "CompiledRule",
    "ComplexityMetadata",
    "DetectionCandidate",
    "DetectionFeature",
    "DetectionPlan",
    "DetectionSchemaError",
    "LintIssue",
    "RuleLintError",
    "compile_candidate",
    "compile_candidates",
    "compile_detection_json",
    "encode_content",
    "lint_candidate",
    "parse_detection_data",
    "parse_detection_json",
]
