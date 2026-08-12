"""将 Suricata 文本规则确定性解析为统一、可序列化的 Rule IR。"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, replace
from typing import Any, Literal, Sequence

from .knowledge import (
    DetectionScope,
    KNOWN_BUFFERS,
    REQUEST_BUFFERS,
    RESPONSE_BUFFERS,
    contains_exploit_marker,
    looks_like_windows_path,
)


Direction = Literal["request", "response"]
FeatureKind = Literal["content", "pcre"]
EvidenceCategory = Literal["endpoint", "parameter", "exploit", "success"]

_EXTRA_STICKY_BUFFERS = frozenset({"payload", "pkt_data", "raw_data"})
_STICKY_BUFFERS = KNOWN_BUFFERS | _EXTRA_STICKY_BUFFERS
_URI_BUFFERS = frozenset({"http.uri", "http.uri.raw", "http.request_line"})
_BODY_BUFFERS = frozenset({"http.request_body"})
_RESPONSE_EVIDENCE_BUFFERS = RESPONSE_BUFFERS | frozenset(
    {"http.response_body", "http.response_header", "http.response_header.raw"}
)
_METHOD_RE = re.compile(r"^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]{0,31}$")
_HEADER_RE = re.compile(
    r"^(?P<action>[A-Za-z][A-Za-z0-9_-]*)\s+"
    r"(?P<protocol>[A-Za-z0-9_.-]+)\s+(?P<rest>.+)$"
)
_PARAMETER_RE = re.compile(
    r"(?:^|[?&;,\s{\[(])['\"]?([A-Za-z_][A-Za-z0-9_.\-\[\]]{0,63})"
    r"['\"]?\s*(?::|=)",
    re.IGNORECASE,
)
_REQUEST_LINE_RE = re.compile(r"^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]*\s+(\S+)")
_DETECTION_SCOPE_RE = re.compile(
    r"^detection_scope\s+(case_specific|exploit_family|success_indicator)$",
    re.IGNORECASE,
)
_LEGACY_CONTENT_BUFFERS = {
    "http_client_body": "http.request_body",
    "http_cookie": "http.cookie",
    "http_header": "http.header",
    "http_host": "http.host",
    "http_method": "http.method",
    "http_raw_header": "http.header.raw",
    "http_raw_host": "http.host.raw",
    "http_raw_uri": "http.uri.raw",
    "http_server_body": "file_data",
    "http_stat_code": "http.stat_code",
    "http_stat_msg": "http.stat_msg",
    "http_uri": "http.uri",
    "http_user_agent": "http.user_agent",
}
_PCRE_BUFFER_MODIFIERS = {
    "C": "http.cookie",
    "D": "http.header.raw",
    "H": "http.header",
    "I": "http.uri.raw",
    "M": "http.method",
    "P": "http.request_body",
    "Q": "file_data",
    "S": "http.stat_code",
    "U": "http.uri",
    "V": "http.user_agent",
    "W": "http.host",
    "Y": "http.stat_msg",
    "Z": "http.host.raw",
}


class RuleIRParseError(ValueError):
    """规则文本无法被可靠转换为 Rule IR。"""

    def __init__(
        self,
        message: str,
        *,
        rule_index: int | None = None,
        line: int | None = None,
    ) -> None:
        self.detail = message
        self.rule_index = rule_index
        self.line = line
        location: list[str] = []
        if rule_index is not None:
            location.append(f"第 {rule_index} 条规则")
        if line is not None:
            location.append(f"第 {line} 行")
        prefix = "，".join(location)
        super().__init__(f"{prefix}：{message}" if prefix else message)


@dataclass(frozen=True, slots=True)
class RuleFeatureIR:
    """一项已绑定 sticky buffer 的 content 或 PCRE 匹配。"""

    buffer: str
    kind: FeatureKind
    content: bytes | None = None
    pcre: str | None = None
    nocase: bool = False
    negated: bool = False
    evidence_categories: tuple[EvidenceCategory, ...] = ()

    @property
    def value(self) -> str:
        """返回适合展示和证据分类的无损转义文本。"""
        if self.content is not None:
            return _display_bytes(self.content)
        assert self.pcre is not None
        return self.pcre

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "buffer": self.buffer,
            "kind": self.kind,
            "value": self.value,
            "nocase": self.nocase,
            "negated": self.negated,
            "evidence_categories": list(self.evidence_categories),
        }
        if self.content is not None:
            result["content_hex"] = self.content.hex().upper()
        else:
            result["pcre"] = self.pcre
        return result


@dataclass(frozen=True, slots=True)
class RuleEvidenceIR:
    """从匹配项中确定性提取的四类规则证据。"""

    endpoint: tuple[str, ...] = ()
    parameter: tuple[str, ...] = ()
    exploit: tuple[str, ...] = ()
    success: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, list[str]]:
        return {
            "endpoint": list(self.endpoint),
            "parameter": list(self.parameter),
            "exploit": list(self.exploit),
            "success": list(self.success),
        }


@dataclass(frozen=True, slots=True)
class RuleIR:
    """一条 Suricata 规则的统一中间表示。"""

    sid: int
    direction: Direction
    detection_scope: DetectionScope
    method: str | None
    features: tuple[RuleFeatureIR, ...]
    evidence: RuleEvidenceIR
    action: str
    protocol: str
    msg: str | None = None
    rev: int | None = None
    metadata: tuple[str, ...] = ()
    classtype: str | None = None
    flow: tuple[str, ...] = ()
    header: str = ""
    other_options: tuple[str, ...] = ()
    raw_rule: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "sid": self.sid,
            "direction": self.direction,
            "detection_scope": self.detection_scope,
            "method": self.method,
            "features": [feature.to_dict() for feature in self.features],
            "evidence": self.evidence.to_dict(),
            "action": self.action,
            "protocol": self.protocol,
            "msg": self.msg,
            "rev": self.rev,
            "metadata": list(self.metadata),
            "classtype": self.classtype,
            "flow": list(self.flow),
            "header": self.header,
            "other_options": list(self.other_options),
            "raw_rule": self.raw_rule,
        }


@dataclass(frozen=True, slots=True)
class _RuleBlock:
    text: str
    line: int


def _display_bytes(value: bytes) -> str:
    """优先显示 UTF-8；二进制数据使用明确的十六进制转义。"""
    try:
        return value.decode("utf-8")
    except UnicodeDecodeError:
        return "".join(
            chr(byte) if 0x20 <= byte <= 0x7E else f"\\x{byte:02X}"
            for byte in value
        )


def _split_rule_blocks(text: str) -> tuple[_RuleBlock, ...]:
    """按括号和引号状态拆分规则，同时保留每条规则的起始行号。"""
    if type(text) is not str:
        raise TypeError("规则文本必须是字符串")

    blocks: list[_RuleBlock] = []
    current: list[str] = []
    start_line = 0
    depth = 0
    saw_open = False
    in_quote = False
    escaped = False

    for line_number, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not current and (not stripped or stripped.startswith("#")):
            continue
        if current and stripped.startswith("#") and not in_quote:
            continue
        if not current:
            start_line = line_number
        current.append(stripped)

        for char in stripped:
            if escaped:
                escaped = False
                continue
            if in_quote and char == "\\":
                escaped = True
                continue
            if char == '"':
                in_quote = not in_quote
                continue
            if in_quote:
                continue
            if char == "(":
                depth += 1
                saw_open = True
            elif char == ")":
                depth -= 1
                if depth < 0:
                    raise RuleIRParseError("出现多余的右括号", line=line_number)

        if saw_open and depth == 0 and not in_quote:
            blocks.append(_RuleBlock(" ".join(current), start_line))
            current = []
            start_line = 0
            saw_open = False
            escaped = False

    if current:
        detail = "规则中的引号未闭合" if in_quote else "规则选项括号未闭合"
        if not saw_open:
            detail = "规则缺少选项括号"
        raise RuleIRParseError(detail, line=start_line)
    if not blocks:
        raise RuleIRParseError("没有发现有效的 Suricata 规则")
    return tuple(blocks)


def _option_bounds(rule: str) -> tuple[int, int]:
    in_quote = False
    escaped = False
    depth = 0
    start = -1
    end = -1
    for index, char in enumerate(rule):
        if escaped:
            escaped = False
            continue
        if in_quote and char == "\\":
            escaped = True
            continue
        if char == '"':
            in_quote = not in_quote
            continue
        if in_quote:
            continue
        if char == "(":
            if start < 0:
                start = index
            depth += 1
        elif char == ")":
            depth -= 1
            if depth == 0:
                end = index
                break
    if start < 0 or end <= start:
        raise RuleIRParseError("规则缺少完整的选项括号")
    if rule[end + 1 :].strip():
        raise RuleIRParseError("规则右括号后存在无法解析的文本")
    return start, end


def _split_options(text: str) -> tuple[str, ...]:
    options: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False
    for char in text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if in_quote and char == "\\":
            current.append(char)
            escaped = True
            continue
        if char == '"':
            current.append(char)
            in_quote = not in_quote
            continue
        if char == ";" and not in_quote:
            option = "".join(current).strip()
            if option:
                options.append(option)
            current = []
            continue
        current.append(char)
    if in_quote:
        raise RuleIRParseError("规则选项中的引号未闭合")
    tail = "".join(current).strip()
    if tail:
        options.append(tail)
    return tuple(options)


def _quoted_value(value: str, option_name: str) -> tuple[str, bool]:
    """拆出带引号选项，返回原始内部文本和是否为否定匹配。"""
    value = value.strip()
    negated = False
    if value.startswith("!"):
        negated = True
        value = value[1:].lstrip()
    if not value.startswith('"'):
        raise RuleIRParseError(f"{option_name} 必须使用双引号")

    escaped = False
    closing = -1
    for index in range(1, len(value)):
        char = value[index]
        if escaped:
            escaped = False
            continue
        if char == "\\":
            escaped = True
            continue
        if char == '"':
            closing = index
            break
    if closing < 0:
        raise RuleIRParseError(f"{option_name} 的双引号未闭合")
    if value[closing + 1 :].strip():
        raise RuleIRParseError(f"{option_name} 引号后存在多余文本")
    return value[1:closing], negated


def _decode_simple_string(value: str, option_name: str) -> str:
    raw, negated = _quoted_value(value, option_name)
    if negated:
        raise RuleIRParseError(f"{option_name} 不允许否定前缀")
    result: list[str] = []
    escaped = False
    for char in raw:
        if escaped:
            result.append(char)
            escaped = False
        elif char == "\\":
            escaped = True
        else:
            result.append(char)
    if escaped:
        raise RuleIRParseError(f"{option_name} 末尾存在孤立反斜杠")
    return "".join(result)


def _decode_content(value: str) -> tuple[bytes, bool]:
    """解码 content 的转义字符和 ``|AA BB|`` 十六进制块。"""
    raw, negated = _quoted_value(value, "content")
    result = bytearray()
    plain: list[str] = []

    def flush_plain() -> None:
        if plain:
            result.extend("".join(plain).encode("utf-8"))
            plain.clear()

    index = 0
    while index < len(raw):
        char = raw[index]
        if char == "\\":
            if index + 1 >= len(raw):
                raise RuleIRParseError("content 末尾存在孤立反斜杠")
            plain.append(raw[index + 1])
            index += 2
            continue
        if char != "|":
            plain.append(char)
            index += 1
            continue

        flush_plain()
        closing = raw.find("|", index + 1)
        if closing < 0:
            raise RuleIRParseError("content 十六进制块缺少结束竖线")
        block = raw[index + 1 : closing].strip()
        tokens = block.split()
        if not tokens or any(re.fullmatch(r"[0-9A-Fa-f]{2}", token) is None for token in tokens):
            raise RuleIRParseError("content 十六进制块必须由两位十六进制字节组成")
        result.extend(int(token, 16) for token in tokens)
        index = closing + 1
    flush_plain()
    return bytes(result), negated


def _pcre_buffer(expression: str) -> str | None:
    """读取旧式 PCRE HTTP buffer 修饰符，并拒绝互相冲突的组合。"""
    if not expression.startswith("/"):
        return None
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
    if closing < 0:
        return None
    buffers = {
        _PCRE_BUFFER_MODIFIERS[modifier]
        for modifier in expression[closing + 1 :]
        if modifier in _PCRE_BUFFER_MODIFIERS
    }
    if len(buffers) > 1:
        raise RuleIRParseError("PCRE 同时声明了多个冲突的 HTTP buffer 修饰符")
    return next(iter(buffers), None)


def _extract_endpoint(text: str, buffer: str) -> str | None:
    if buffer not in _URI_BUFFERS:
        return None
    candidate = text.strip()
    if buffer == "http.request_line":
        match = _REQUEST_LINE_RE.match(candidate)
        if match is None:
            return None
        candidate = match.group(1)
    candidate = candidate.split("?", 1)[0]
    if not candidate.startswith("/") or candidate in {"/", "//"}:
        return None
    return candidate


def _feature_evidence(feature: RuleFeatureIR) -> tuple[tuple[str, str], ...]:
    text = feature.value
    evidence: list[tuple[str, str]] = []
    # PCRE 的开头斜杠是表达式分隔符，不能被当成 URI endpoint。
    endpoint = (
        _extract_endpoint(text, feature.buffer)
        if feature.kind == "content"
        else None
    )
    if endpoint is not None:
        evidence.append(("endpoint", endpoint))

    if feature.buffer in _URI_BUFFERS | _BODY_BUFFERS:
        evidence.extend(("parameter", match) for match in _PARAMETER_RE.findall(text))

    if feature.buffer in _RESPONSE_EVIDENCE_BUFFERS:
        evidence.append(("success", text))
    elif contains_exploit_marker(text) or looks_like_windows_path(text) or not evidence:
        evidence.append(("exploit", text))
    return tuple(evidence)


def _classify_features(
    features: Sequence[RuleFeatureIR],
) -> tuple[tuple[RuleFeatureIR, ...], RuleEvidenceIR]:
    endpoints: list[str] = []
    parameters: list[str] = []
    exploits: list[str] = []
    successes: list[str] = []
    classified: list[RuleFeatureIR] = []

    def add_unique(target: list[str], value: str) -> None:
        if value and value not in target:
            target.append(value)

    for feature in features:
        items = _feature_evidence(feature)
        categories: list[EvidenceCategory] = []
        for category, value in items:
            typed_category: EvidenceCategory = category  # type: ignore[assignment]
            if typed_category not in categories:
                categories.append(typed_category)
            if category == "endpoint":
                add_unique(endpoints, value)
            elif category == "parameter":
                add_unique(parameters, value)
            elif category == "exploit":
                add_unique(exploits, value)
            else:
                add_unique(successes, value)
        classified.append(replace(feature, evidence_categories=tuple(categories)))

    return (
        tuple(classified),
        RuleEvidenceIR(
            endpoint=tuple(endpoints),
            parameter=tuple(parameters),
            exploit=tuple(exploits),
            success=tuple(successes),
        ),
    )


def _detection_scope(
    metadata: Sequence[str],
    direction: Direction,
) -> DetectionScope:
    """读取生成器写入的 scope；旧规则按方向使用保守默认值。"""
    scopes: list[DetectionScope] = []
    for value in metadata:
        match = _DETECTION_SCOPE_RE.fullmatch(value.strip())
        if match is None:
            continue
        scope: DetectionScope = match.group(1).casefold()  # type: ignore[assignment]
        if scope not in scopes:
            scopes.append(scope)
    if len(scopes) > 1:
        raise RuleIRParseError("metadata 包含冲突的 detection_scope")
    if scopes:
        return scopes[0]
    return "success_indicator" if direction == "response" else "case_specific"


def _parse_positive_int(value: str, option_name: str) -> int:
    value = value.strip()
    if re.fullmatch(r"[0-9]+", value) is None:
        raise RuleIRParseError(f"{option_name} 必须是正整数")
    number = int(value)
    if number <= 0:
        raise RuleIRParseError(f"{option_name} 必须是正整数")
    return number


def _direction_from_rule(
    flow: Sequence[str],
    feature_buffers: Sequence[str],
) -> Direction:
    flow_values = {value.casefold() for value in flow}
    has_to_server = "to_server" in flow_values
    has_to_client = "to_client" in flow_values
    if has_to_server and has_to_client:
        raise RuleIRParseError("flow 不能同时包含 to_server 和 to_client")

    uses_request = any(buffer in REQUEST_BUFFERS for buffer in feature_buffers)
    uses_response = any(buffer in RESPONSE_BUFFERS for buffer in feature_buffers)
    if uses_request and uses_response:
        raise RuleIRParseError("同一规则混用了请求和响应 sticky buffer")
    if has_to_server and uses_response:
        raise RuleIRParseError("flow:to_server 与响应 sticky buffer 冲突")
    if has_to_client and uses_request:
        raise RuleIRParseError("flow:to_client 与请求 sticky buffer 冲突")
    if has_to_server:
        return "request"
    if has_to_client:
        return "response"
    if uses_request:
        return "request"
    if uses_response:
        return "response"
    raise RuleIRParseError("无法从 flow 或 sticky buffer 确定请求/响应方向")


def _parse_rule_block(block: _RuleBlock, rule_index: int) -> RuleIR:
    try:
        start, end = _option_bounds(block.text)
        header = block.text[:start].strip()
        header_match = _HEADER_RE.fullmatch(header)
        if header_match is None or not re.search(r"(?:->|<>|<-)", header_match.group("rest")):
            raise RuleIRParseError("规则头格式无效")

        action = header_match.group("action").casefold()
        protocol = header_match.group("protocol").casefold()
        options = _split_options(block.text[start + 1 : end])
        active_buffer = "payload"
        features: list[RuleFeatureIR] = []
        last_content_index: int | None = None
        sid: int | None = None
        rev: int | None = None
        msg: str | None = None
        classtype: str | None = None
        flow: list[str] = []
        metadata: list[str] = []
        other_options: list[str] = []

        for option in options:
            if ":" in option:
                name, raw_value = option.split(":", 1)
                name = name.strip().casefold()
            else:
                name = option.strip().casefold()
                raw_value = ""

            if not raw_value and name in _STICKY_BUFFERS:
                active_buffer = name
                last_content_index = None
            elif name == "content":
                content, negated = _decode_content(raw_value)
                features.append(
                    RuleFeatureIR(
                        buffer=active_buffer,
                        kind="content",
                        content=content,
                        negated=negated,
                    )
                )
                last_content_index = len(features) - 1
            elif name == "pcre":
                pcre, negated = _quoted_value(raw_value, "pcre")
                embedded_buffer = _pcre_buffer(pcre)
                if (
                    embedded_buffer is not None
                    and active_buffer != "payload"
                    and active_buffer != embedded_buffer
                ):
                    raise RuleIRParseError(
                        "PCRE buffer 修饰符与当前 sticky buffer 冲突"
                    )
                features.append(
                    RuleFeatureIR(
                        buffer=embedded_buffer or active_buffer,
                        kind="pcre",
                        pcre=pcre,
                        negated=negated,
                    )
                )
                last_content_index = None
            elif not raw_value and name in _LEGACY_CONTENT_BUFFERS:
                if last_content_index is None:
                    raise RuleIRParseError(
                        f"旧式 {name} 前没有可关联的 content"
                    )
                feature = features[last_content_index]
                target_buffer = _LEGACY_CONTENT_BUFFERS[name]
                if feature.buffer not in {"payload", target_buffer}:
                    raise RuleIRParseError(
                        f"旧式 {name} 与当前 sticky buffer 冲突"
                    )
                features[last_content_index] = replace(
                    feature,
                    buffer=target_buffer,
                )
            elif name == "nocase" and not raw_value:
                if last_content_index is None:
                    raise RuleIRParseError("nocase 前没有可关联的 content")
                feature = features[last_content_index]
                if feature.nocase:
                    raise RuleIRParseError("同一个 content 重复声明 nocase")
                features[last_content_index] = replace(feature, nocase=True)
            elif name == "sid":
                if sid is not None:
                    raise RuleIRParseError("同一规则重复声明 sid")
                sid = _parse_positive_int(raw_value, "sid")
            elif name == "rev":
                if rev is not None:
                    raise RuleIRParseError("同一规则重复声明 rev")
                rev = _parse_positive_int(raw_value, "rev")
            elif name == "msg":
                if msg is not None:
                    raise RuleIRParseError("同一规则重复声明 msg")
                msg = _decode_simple_string(raw_value, "msg")
            elif name == "flow":
                flow.extend(
                    value.strip().casefold()
                    for value in raw_value.split(",")
                    if value.strip()
                )
            elif name == "metadata":
                metadata.extend(value.strip() for value in raw_value.split(",") if value.strip())
            elif name == "classtype":
                if classtype is not None:
                    raise RuleIRParseError("同一规则重复声明 classtype")
                classtype = raw_value.strip() or None
            else:
                other_options.append(option)

        if sid is None:
            raise RuleIRParseError("规则缺少 sid")

        all_buffers = [feature.buffer for feature in features]
        direction = _direction_from_rule(flow, all_buffers)
        method: str | None = None
        retained_features: list[RuleFeatureIR] = []
        for feature in features:
            if feature.buffer != "http.method":
                retained_features.append(feature)
                continue
            if feature.kind != "content" or feature.content is None or feature.negated:
                # 正则方法条件无法压缩成单个 method 字段，按原特征无损保留。
                retained_features.append(feature)
                continue
            if method is not None:
                raise RuleIRParseError("同一规则包含多个 HTTP method")
            try:
                method = feature.content.decode("ascii").upper()
            except UnicodeDecodeError as exc:
                raise RuleIRParseError("HTTP method 必须是 ASCII") from exc
            if _METHOD_RE.fullmatch(method) is None:
                raise RuleIRParseError("HTTP method 格式无效")
        if direction == "response" and method is not None:
            raise RuleIRParseError("响应规则不能包含 HTTP method")

        classified, evidence = _classify_features(retained_features)
        detection_scope = _detection_scope(metadata, direction)
        return RuleIR(
            sid=sid,
            direction=direction,
            detection_scope=detection_scope,
            method=method,
            features=classified,
            evidence=evidence,
            action=action,
            protocol=protocol,
            msg=msg,
            rev=rev,
            metadata=tuple(metadata),
            classtype=classtype,
            flow=tuple(flow),
            header=header,
            other_options=tuple(other_options),
            raw_rule=block.text,
        )
    except RuleIRParseError as exc:
        if exc.rule_index is not None or exc.line is not None:
            raise
        raise RuleIRParseError(
            exc.detail,
            rule_index=rule_index,
            line=block.line,
        ) from exc


def parse_suricata_rule(text: str) -> RuleIR:
    """解析恰好一条 Suricata 规则。"""
    blocks = _split_rule_blocks(text)
    if len(blocks) != 1:
        raise RuleIRParseError(f"预期一条规则，实际得到 {len(blocks)} 条")
    return _parse_rule_block(blocks[0], 1)


def parse_suricata_rules(text: str) -> tuple[RuleIR, ...]:
    """解析 .rules 文本，并拒绝重复 SID。"""
    rules = tuple(
        _parse_rule_block(block, index)
        for index, block in enumerate(_split_rule_blocks(text), start=1)
    )
    seen: set[int] = set()
    for index, rule in enumerate(rules, start=1):
        if rule.sid in seen:
            raise RuleIRParseError(f"SID {rule.sid} 重复", rule_index=index)
        seen.add(rule.sid)
    return rules


def rule_ir_to_dict(rule: RuleIR) -> dict[str, Any]:
    """把一条 Rule IR 转成只含 JSON 基础类型的字典。"""
    if not isinstance(rule, RuleIR):
        raise TypeError("rule 必须是 RuleIR")
    return rule.to_dict()


def serialize_rule_ir(
    rules: RuleIR | Sequence[RuleIR],
    *,
    indent: int | None = 2,
) -> str:
    """将一条或多条 Rule IR 序列化为稳定的 UTF-8 JSON 文本。"""
    values = (rules,) if isinstance(rules, RuleIR) else tuple(rules)
    if not all(isinstance(rule, RuleIR) for rule in values):
        raise TypeError("rules 必须是 RuleIR 或 RuleIR 序列")
    return json.dumps(
        {"rules": [rule.to_dict() for rule in values]},
        ensure_ascii=False,
        indent=indent,
        sort_keys=True,
    )


__all__ = [
    "Direction",
    "EvidenceCategory",
    "FeatureKind",
    "RuleEvidenceIR",
    "RuleFeatureIR",
    "RuleIR",
    "RuleIRParseError",
    "parse_suricata_rule",
    "parse_suricata_rules",
    "rule_ir_to_dict",
    "serialize_rule_ir",
]
