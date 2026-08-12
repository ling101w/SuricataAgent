"""根据规则、样本矩阵和验证结果生成确定性的失败诊断。"""

from __future__ import annotations

import re
from dataclasses import dataclass, replace
from typing import Any, Literal, Mapping, Sequence
from urllib.parse import unquote_to_bytes

from .knowledge import (
    KNOWN_BUFFERS,
    REQUEST_BUFFERS,
    RESPONSE_BUFFERS,
    is_structural_match,
)

_HTTP_SEPARATOR_RE = re.compile(br"\r\n\r\n|\n\n|\r\r")
_LINE_SEPARATOR_RE = re.compile(br"\r\n|\n|\r")
_PERCENT_ESCAPE_RE = re.compile(r"%[0-9A-Fa-f]{2}")
_PCRE_OUTPUT_RE = re.compile(
    r"(?:pcre.{0,100}(?:error|invalid|parse|bad option|format))|"
    r"(?:(?:error|invalid|parse|bad option|format).{0,100}pcre)",
    re.IGNORECASE | re.DOTALL,
)
_SYNTAX_ESCAPE_OUTPUT_RE = re.compile(
    r"unterminated|unclosed|missing.{0,20}quote|invalid.{0,20}(?:escape|hex)|"
    r"bad option value formatting|unterminated string|closing quote",
    re.IGNORECASE | re.DOTALL,
)
@dataclass(frozen=True)
class _RuleFeature:
    rule_index: int
    feature_index: int
    buffer: str
    kind: Literal["content", "pcre"]
    value: str
    nocase: bool = False

    @property
    def label(self) -> str:
        if self.kind == "pcre":
            return f"pcre:{self.value}"
        return self.value


@dataclass(frozen=True)
class _Finding:
    failure_type: str
    suspected_reason: str
    suggestion: str
    sample_names: tuple[str, ...] = ()
    features: tuple[str, ...] = ()
    evidence_locations: tuple[str, ...] = ()

    def public_dict(self) -> dict[str, Any]:
        return {
            "failure_type": self.failure_type,
            "suspected_reason": self.suspected_reason,
            "suggestion": self.suggestion,
            "sample_names": list(self.sample_names),
            "features": list(self.features),
            "evidence_locations": list(self.evidence_locations),
        }


def _field(value: object, name: str, default: object = None) -> object:
    if isinstance(value, Mapping):
        return value.get(name, default)
    return getattr(value, name, default)


def _unique(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _split_options(option_text: str) -> tuple[list[str], list[str]]:
    options: list[str] = []
    errors: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False

    for char in option_text:
        current.append(char)
        if escaped:
            escaped = False
            continue
        if in_quote and char == "\\":
            escaped = True
            continue
        if char == '"':
            in_quote = not in_quote
            continue
        if char == ";" and not in_quote:
            option = "".join(current[:-1]).strip()
            if option:
                options.append(option)
            current = []

    trailing = "".join(current).strip()
    if trailing:
        options.append(trailing)
    if in_quote:
        errors.append("规则选项包含未闭合的引号")
    if escaped:
        errors.append("规则选项以未完成的反斜杠转义结尾")
    return options, errors


def _rule_option_sections(rule_text: str) -> tuple[list[str], list[str]]:
    sections: list[str] = []
    errors: list[str] = []
    cursor = 0

    while True:
        start = rule_text.find("(", cursor)
        if start < 0:
            break
        depth = 1
        in_quote = False
        escaped = False
        index = start + 1
        while index < len(rule_text):
            char = rule_text[index]
            if escaped:
                escaped = False
            elif in_quote and char == "\\":
                escaped = True
            elif char == '"':
                in_quote = not in_quote
            elif not in_quote and char == "(":
                depth += 1
            elif not in_quote and char == ")":
                depth -= 1
                if depth == 0:
                    sections.append(rule_text[start + 1 : index])
                    cursor = index + 1
                    break
            index += 1
        else:
            # 即使外层括号因引号错误未被识别，也保留内容供进一步诊断。
            end = rule_text.rfind(")")
            sections.append(rule_text[start + 1 : end if end > start else None])
            errors.append("规则选项缺少可识别的结束括号或存在未闭合引号")
            break

    if not sections:
        errors.append("规则中没有可识别的选项区")
    return sections, errors


def _decode_content(value: str) -> tuple[str, list[str]]:
    output = bytearray()
    errors: list[str] = []
    index = 0
    while index < len(value):
        char = value[index]
        if char == "|":
            end = value.find("|", index + 1)
            if end < 0:
                errors.append("content 包含未闭合的十六进制块")
                output.extend(value[index:].encode("utf-8"))
                break
            hex_text = value[index + 1 : end].strip()
            parts = hex_text.split()
            if not parts or any(re.fullmatch(r"[0-9A-Fa-f]{2}", part) is None for part in parts):
                errors.append("content 包含无效的十六进制字节")
                output.extend(value[index : end + 1].encode("utf-8"))
            else:
                output.extend(int(part, 16) for part in parts)
            index = end + 1
            continue
        if char == "\\" and index + 1 < len(value):
            if value[index + 1] not in {'"', "\\", ";", ":", "|"}:
                errors.append("content 包含含义不明确的单反斜杠转义")
            output.extend(value[index + 1].encode("utf-8"))
            index += 2
            continue
        if char == "\\":
            errors.append("content 以未完成的反斜杠转义结尾")
            output.extend(char.encode("utf-8"))
            index += 1
            continue
        output.extend(char.encode("utf-8"))
        index += 1
    return output.decode("latin-1"), errors


def _quoted_option(option: str, keyword: str) -> tuple[str | None, str | None]:
    match = re.match(rf"^{re.escape(keyword)}\s*:\s*(.*)$", option, re.IGNORECASE)
    if match is None:
        return None, None
    rendered = match.group(1).strip()
    if len(rendered) < 2 or not rendered.startswith('"') or not rendered.endswith('"'):
        return None, f"{keyword} 必须使用成对双引号"
    return rendered[1:-1], None


def _parse_rule(rule_text: str) -> tuple[list[_RuleFeature], str | None, list[str]]:
    sections, errors = _rule_option_sections(rule_text)
    features: list[_RuleFeature] = []
    directions: set[str] = set()

    for rule_index, section in enumerate(sections, start=1):
        options, option_errors = _split_options(section)
        errors.extend(option_errors)
        active_buffer = "payload"
        for option in options:
            lowered = option.casefold()
            if lowered in KNOWN_BUFFERS:
                active_buffer = lowered
                continue
            if lowered.startswith("flow:"):
                values = {item.strip() for item in lowered.partition(":")[2].split(",")}
                if "to_server" in values:
                    directions.add("request")
                if "to_client" in values:
                    directions.add("response")
                continue

            content, content_error = _quoted_option(option, "content")
            if content_error:
                errors.append(content_error)
            if content is not None:
                decoded, decode_errors = _decode_content(content)
                errors.extend(decode_errors)
                features.append(
                    _RuleFeature(
                        rule_index,
                        len(features) + 1,
                        active_buffer,
                        "content",
                        decoded,
                    )
                )
                continue

            pcre, pcre_error = _quoted_option(option, "pcre")
            if pcre_error:
                errors.append(pcre_error)
            if pcre is not None:
                features.append(
                    _RuleFeature(
                        rule_index,
                        len(features) + 1,
                        active_buffer,
                        "pcre",
                        pcre,
                    )
                )
                continue

            if lowered == "nocase" and features and features[-1].kind == "content":
                features[-1] = replace(features[-1], nocase=True)

    direction: str | None
    if len(directions) == 1:
        direction = next(iter(directions))
    elif len(directions) > 1:
        direction = "mixed"
        errors.append("规则同时包含 to_server 和 to_client 方向")
    else:
        direction = None
    return features, direction, _unique(errors)


def _candidate_value(candidate: object | None) -> object | None:
    if candidate is None:
        return None
    candidates = _field(candidate, "candidates")
    if isinstance(candidates, Sequence) and not isinstance(candidates, (str, bytes)):
        return candidates[0] if candidates else None
    return candidate


def _candidate_direction(candidate: object | None) -> str | None:
    value = _candidate_value(candidate)
    direction = _field(value, "direction") if value is not None else None
    return str(direction) if direction in {"request", "response"} else None


def _candidate_features(candidate: object | None) -> list[_RuleFeature]:
    value = _candidate_value(candidate)
    if value is None:
        return []
    features: list[_RuleFeature] = []
    method = _field(value, "method")
    if isinstance(method, str) and method:
        features.append(_RuleFeature(1, 1, "http.method", "content", method))
    raw_features = _field(value, "features", ())
    if not isinstance(raw_features, Sequence) or isinstance(raw_features, (str, bytes)):
        return features
    for raw_feature in raw_features:
        buffer = _field(raw_feature, "buffer")
        content = _field(raw_feature, "content")
        pcre = _field(raw_feature, "pcre")
        nocase = _field(raw_feature, "nocase", False)
        if not isinstance(buffer, str):
            continue
        if isinstance(content, str):
            features.append(
                _RuleFeature(1, len(features) + 1, buffer, "content", content, bool(nocase))
            )
        elif isinstance(pcre, str):
            features.append(
                _RuleFeature(1, len(features) + 1, buffer, "pcre", pcre)
            )
    return features


def _message_bytes(message: object) -> bytes | None:
    if isinstance(message, bytes):
        return message
    if isinstance(message, str):
        return message.encode("utf-8")
    return None


def _parse_message(message: object) -> tuple[str, list[tuple[str, str]], str]:
    raw = _message_bytes(message)
    if raw is None:
        return "", [], ""
    separator = _HTTP_SEPARATOR_RE.search(raw)
    if separator is None:
        header_bytes, body_bytes = raw, b""
    else:
        header_bytes = raw[: separator.start()]
        body_bytes = raw[separator.end() :]
    lines = _LINE_SEPARATOR_RE.split(header_bytes)
    start_line = lines[0].decode("latin-1", errors="replace") if lines else ""
    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if line[:1] in {b" ", b"\t"} and headers:
            name, previous = headers[-1]
            headers[-1] = (
                name,
                previous + " " + line.strip().decode("latin-1", errors="replace"),
            )
            continue
        name, marker, header_value = line.partition(b":")
        if not marker:
            continue
        headers.append(
            (
                name.decode("latin-1", errors="replace").strip(),
                header_value.decode("latin-1", errors="replace").strip(),
            )
        )
    return start_line, headers, body_bytes.decode("latin-1", errors="replace")


def _header_value(headers: Sequence[tuple[str, str]], name: str) -> str:
    return "\n".join(value for key, value in headers if key.casefold() == name.casefold())


def _render_headers(headers: Sequence[tuple[str, str]]) -> str:
    return "\r\n".join(f"{name}: {value}" for name, value in headers)


def _normalize_uri(target: str) -> str:
    try:
        return unquote_to_bytes(target).decode("latin-1", errors="replace")
    except (UnicodeEncodeError, ValueError):
        return target


def _sample_views(sample: object, direction: str | None) -> dict[str, str]:
    request_line, request_headers, request_body = _parse_message(_field(sample, "request"))
    response_line, response_headers, response_body = _parse_message(_field(sample, "response"))

    request_parts = request_line.split(" ", 2)
    method = request_parts[0] if request_parts else ""
    target = request_parts[1] if len(request_parts) > 1 else ""
    request_protocol = request_parts[2] if len(request_parts) > 2 else ""
    response_parts = response_line.split(" ", 2)
    response_protocol = response_parts[0] if response_parts else ""
    status_code = response_parts[1] if len(response_parts) > 1 else ""
    status_message = response_parts[2] if len(response_parts) > 2 else ""
    request_header_text = _render_headers(request_headers)
    response_header_text = _render_headers(response_headers)

    views = {
        "payload": "\r\n\r\n".join(
            value
            for value in (
                request_line + "\r\n" + request_header_text,
                request_body,
                response_line + "\r\n" + response_header_text,
                response_body,
            )
            if value
        ),
        "http.method": method,
        "http.uri.raw": target,
        "http.uri": _normalize_uri(target),
        "http.request_line": request_line,
        "http.request_header": request_header_text,
        "http.request_header.raw": request_header_text,
        "http.request_body": request_body,
        "http.user_agent": _header_value(request_headers, "User-Agent"),
        "http.host": _header_value(request_headers, "Host").casefold(),
        "http.host.raw": _header_value(request_headers, "Host"),
        "http.cookie": _header_value(request_headers, "Cookie"),
        "http.accept": _header_value(request_headers, "Accept"),
        "http.accept_enc": _header_value(request_headers, "Accept-Encoding"),
        "http.accept_lang": _header_value(request_headers, "Accept-Language"),
        "http.referer": _header_value(request_headers, "Referer"),
        "http.response_line": response_line,
        "http.response_header": response_header_text,
        "http.response_header.raw": response_header_text,
        "http.response_body": response_body,
        "file_data": response_body,
        "http.location": _header_value(response_headers, "Location"),
        "http.stat_code": status_code,
        "http.stat_msg": status_message,
    }
    if direction == "response":
        active_line = response_line
        active_headers = response_headers
        active_header_text = response_header_text
        active_protocol = response_protocol
    else:
        active_line = request_line
        active_headers = request_headers
        active_header_text = request_header_text
        active_protocol = request_protocol
    views.update(
        {
            "http.header": active_header_text,
            "http.header.raw": active_header_text,
            "http.start": active_line + ("\r\n" + active_header_text if active_header_text else ""),
            "http.protocol": active_protocol,
            "http.connection": _header_value(active_headers, "Connection"),
            "http.content_len": _header_value(active_headers, "Content-Length"),
            "http.content_type": _header_value(active_headers, "Content-Type"),
        }
    )
    return views


def _parse_pcre(expression: str) -> tuple[re.Pattern[str] | None, str | None]:
    if not expression.startswith("/"):
        return None, "PCRE 缺少开始分隔符"
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
        return None, "PCRE 缺少结束分隔符或表达式为空"
    modifiers = expression[closing + 1 :]
    if modifiers and re.fullmatch(r"[A-Za-z]+", modifiers) is None:
        return None, "PCRE 修饰符格式无效"
    flags = 0
    if "i" in modifiers:
        flags |= re.IGNORECASE
    if "m" in modifiers:
        flags |= re.MULTILINE
    if "s" in modifiers:
        flags |= re.DOTALL
    if "x" in modifiers:
        flags |= re.VERBOSE
    try:
        return re.compile(expression[1:closing], flags), None
    except re.error as exc:
        return None, f"PCRE 无法解析：{exc}"


def _feature_matches(feature: _RuleFeature, payload: str) -> tuple[bool, str | None]:
    if feature.kind == "content":
        if feature.nocase:
            return feature.value.casefold() in payload.casefold(), None
        return feature.value in payload, None
    pattern, error = _parse_pcre(feature.value)
    if pattern is None:
        return False, error
    return pattern.search(payload) is not None, None


def _location_candidates(feature: _RuleFeature, views: Mapping[str, str]) -> list[str]:
    preferred_order = (
        "http.method",
        "http.uri.raw",
        "http.uri",
        "http.user_agent",
        "http.host.raw",
        "http.cookie",
        "http.request_body",
        "http.request_header.raw",
        "http.response_body",
        "file_data",
        "http.response_header.raw",
        "http.response_line",
    )
    locations: list[str] = []
    for buffer in preferred_order:
        payload = views.get(buffer, "")
        if not payload:
            continue
        matched, error = _feature_matches(feature, payload)
        if matched and error is None:
            locations.append(buffer)
    return _unique(locations)


def _analyze_sample(
    sample: object,
    sample_result: Mapping[str, object],
    features: Sequence[_RuleFeature],
    direction: str | None,
) -> dict[str, Any]:
    views = _sample_views(sample, direction)
    matched: list[str] = []
    unmatched: list[str] = []
    locations: dict[str, list[str]] = {}
    pcre_errors: dict[str, str] = {}
    feature_matches: dict[int, bool] = {}

    for feature in features:
        payload = views.get(feature.buffer, "")
        is_match, error = _feature_matches(feature, payload)
        feature_matches[feature.feature_index] = is_match
        if is_match:
            matched.append(feature.label)
        else:
            unmatched.append(feature.label)
            found_locations = _location_candidates(feature, views)
            if found_locations:
                locations[feature.label] = found_locations
        if error:
            pcre_errors[feature.label] = error

    return {
        "name": str(sample_result.get("name", _field(sample, "name", "sample"))),
        "expected": str(sample_result.get("expected", _field(sample, "expected", "alert"))),
        "reason": str(sample_result.get("reason", _field(sample, "reason", ""))),
        "matched_sids": list(sample_result.get("matched_sids", [])),
        "passed": bool(sample_result.get("passed", False)),
        "matched_features": _unique(matched),
        "unmatched_features": _unique(unmatched),
        "evidence_locations": locations,
        "pcre_errors": pcre_errors,
        "feature_matches": feature_matches,
        "_views": views,
    }


def _sample_lookup(samples: Sequence[object]) -> dict[str, object]:
    lookup: dict[str, object] = {}
    for sample in samples:
        name = _field(sample, "name")
        if isinstance(name, str):
            lookup[name] = sample
    return lookup


def _validation_sample_results(
    validation: Mapping[str, Any], samples: Sequence[object]
) -> list[Mapping[str, object]]:
    raw_results = validation.get("sample_results", [])
    if isinstance(raw_results, Sequence) and not isinstance(raw_results, (str, bytes)):
        results = [item for item in raw_results if isinstance(item, Mapping)]
        if results:
            return results
    return [
        {
            "name": str(_field(sample, "name", f"sample-{index}")),
            "expected": str(_field(sample, "expected", "alert")),
            "reason": str(_field(sample, "reason", "")),
            "matched_sids": [],
            "passed": bool(validation.get("passed", False)),
        }
        for index, sample in enumerate(samples, start=1)
    ]


def _is_structural_feature(feature: _RuleFeature) -> bool:
    return is_structural_match(feature.buffer, feature.value, kind=feature.kind)


def _add_finding(findings: list[_Finding], finding: _Finding) -> None:
    if any(item.failure_type == finding.failure_type for item in findings):
        return
    findings.append(finding)


def _safe_public_analysis(analysis: Mapping[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in analysis.items()
        if not key.startswith("_") and key != "feature_matches"
    }


def diagnose_candidate(
    rule_text: str,
    validation: Mapping[str, Any],
    samples: Sequence[object],
    candidate_plan: object | None = None,
) -> dict[str, Any]:
    """诊断一个候选规则，不执行 Suricata，也不修改任何输入或产物。"""
    parsed_features, rule_direction, parse_errors = _parse_rule(rule_text)
    features = parsed_features or _candidate_features(candidate_plan)
    candidate_direction = _candidate_direction(candidate_plan)
    direction = (
        rule_direction
        if rule_direction in {"request", "response"}
        else candidate_direction
    )

    sample_results = _validation_sample_results(validation, samples)
    sample_by_name = _sample_lookup(samples)
    analyses: list[dict[str, Any]] = []
    for result in sample_results:
        name = str(result.get("name", "sample"))
        sample = sample_by_name.get(name)
        if sample is None:
            continue
        analyses.append(_analyze_sample(sample, result, features, direction))

    failed_analyses = [item for item in analyses if not item["passed"]]
    failed_positive = [item for item in failed_analyses if item["expected"] == "alert"]
    failed_negative = [item for item in failed_analyses if item["expected"] == "no_alert"]
    positive_analyses = [item for item in analyses if item["expected"] == "alert"]
    focus = failed_positive or failed_negative

    matched_features: list[str] = []
    unmatched_features: list[str] = []
    for feature in features:
        states = [
            bool(item["feature_matches"].get(feature.feature_index, False))
            for item in focus
        ]
        if states and all(states):
            matched_features.append(feature.label)
        elif states:
            unmatched_features.append(feature.label)

    findings: list[_Finding] = []
    output = str(validation.get("command_output", ""))
    syntax_failed = validation.get("syntax_ok") is False or validation.get("error_code") in {
        "RULE_LOAD_ERROR",
        "STATIC_RULE_ERROR",
    }
    pcre_errors = {
        label: error
        for analysis in analyses
        for label, error in analysis["pcre_errors"].items()
    }
    for feature in features:
        if feature.kind != "pcre":
            continue
        _, error = _parse_pcre(feature.value)
        if error:
            pcre_errors[feature.label] = error
    if syntax_failed and (_PCRE_OUTPUT_RE.search(output) or pcre_errors):
        details = tuple(pcre_errors) or tuple(
            feature.label for feature in features if feature.kind == "pcre"
        )
        _add_finding(
            findings,
            _Finding(
                "PCRE_PARSE_ERROR",
                "Suricata 或本地解析器无法解析规则中的 PCRE 表达式。",
                "修正 PCRE 的分隔符、括号和修饰符；能用 content 表达时优先改用 content。",
                features=details,
            ),
        )

    if syntax_failed and (
        parse_errors
        or _SYNTAX_ESCAPE_OUTPUT_RE.search(output)
        and not _PCRE_OUTPUT_RE.search(output)
    ):
        _add_finding(
            findings,
            _Finding(
                "SYNTAX_ESCAPE_ERROR",
                "规则包含未闭合引号、非法十六进制块或不完整的反斜杠转义。",
                "不要手工拼接规则值；将原始特征交给确定性编译器统一编码。",
                features=tuple(parse_errors),
            ),
        )

    response_features = [feature for feature in features if feature.buffer in RESPONSE_BUFFERS]
    request_features = [feature for feature in features if feature.buffer in REQUEST_BUFFERS]
    response_locations: list[str] = []
    for analysis in failed_positive:
        for locations in analysis["evidence_locations"].values():
            response_locations.extend(
                location for location in locations if location in RESPONSE_BUFFERS
            )
    if direction == "request" and (response_features or response_locations):
        _add_finding(
            findings,
            _Finding(
                "RESPONSE_FEATURE_IN_REQUEST_RULE",
                "to_server 请求规则使用了响应 sticky buffer，或待匹配证据只存在于响应报文。",
                "将响应证据拆成 to_client 候选；请求候选只保留请求侧利用特征。",
                sample_names=tuple(item["name"] for item in failed_positive),
                features=tuple(feature.label for feature in response_features),
                evidence_locations=tuple(_unique(response_locations)),
            ),
        )

    direction_conflict = (
        direction == "request" and bool(response_features)
        or direction == "response" and bool(request_features)
        or rule_direction == "mixed"
        or rule_direction is not None
        and candidate_direction is not None
        and rule_direction != candidate_direction
    )
    if direction_conflict:
        _add_finding(
            findings,
            _Finding(
                "WRONG_DIRECTION",
                "flow 方向、候选方向与所用 HTTP sticky buffer 不一致。",
                "请求特征使用 established,to_server，响应特征使用 established,to_client，并避免跨方向混用。",
                features=tuple(
                    feature.label
                    for feature in (*request_features, *response_features)
                ),
            ),
        )

    normalized_features: list[str] = []
    normalized_samples: list[str] = []
    for feature in features:
        if feature.kind != "content" or feature.buffer not in {"http.uri", "http.uri.raw"}:
            continue
        counterpart = "http.uri" if feature.buffer == "http.uri.raw" else "http.uri.raw"
        for analysis in failed_positive:
            if analysis["feature_matches"].get(feature.feature_index, False):
                continue
            views = analysis["_views"]
            counterpart_match, _ = _feature_matches(feature, views.get(counterpart, ""))
            representation_sensitive = (
                _PERCENT_ESCAPE_RE.search(views.get("http.uri.raw", "")) is not None
                or _PERCENT_ESCAPE_RE.search(feature.value) is not None
                or "\\" in feature.value
            )
            if counterpart_match or representation_sensitive and "url-encoded" in analysis["name"]:
                normalized_features.append(feature.label)
                normalized_samples.append(analysis["name"])
    if normalized_features:
        _add_finding(
            findings,
            _Finding(
                "NORMALIZED_RAW_MISMATCH",
                "URI 特征在原始值与标准化值之间的表示不一致，导致编码变体漏报。",
                "按证据语义选择 http.uri 或 http.uri.raw；需要兼容两种表示时生成独立候选或使用受控 PCRE。",
                sample_names=tuple(_unique(normalized_samples)),
                features=tuple(_unique(normalized_features)),
                evidence_locations=("http.uri", "http.uri.raw"),
            ),
        )

    wrong_buffer_features: list[str] = []
    wrong_buffer_locations: list[str] = []
    wrong_buffer_samples: list[str] = []
    for analysis in failed_positive:
        for feature in features:
            if analysis["feature_matches"].get(feature.feature_index, False):
                continue
            locations = analysis["evidence_locations"].get(feature.label, [])
            locations = [
                location
                for location in locations
                if location != feature.buffer
                and {location, feature.buffer} != {"http.uri", "http.uri.raw"}
            ]
            if locations:
                wrong_buffer_features.append(feature.label)
                wrong_buffer_locations.extend(locations)
                wrong_buffer_samples.append(analysis["name"])
    if wrong_buffer_features:
        _add_finding(
            findings,
            _Finding(
                "WRONG_STICKY_BUFFER",
                "未命中特征存在于报文中，但不在规则声明的 sticky buffer 内。",
                "把特征放入证据实际所在的 sticky buffer，并保持每个 content 与其 buffer 相邻。",
                sample_names=tuple(_unique(wrong_buffer_samples)),
                features=tuple(_unique(wrong_buffer_features)),
                evidence_locations=tuple(_unique(wrong_buffer_locations)),
            ),
        )

    mixed_features: list[str] = []
    mixed_samples: list[str] = []
    for feature in features:
        if feature.kind != "content" or len(positive_analyses) < 2:
            continue
        matched_by_sample = [
            bool(item["feature_matches"].get(feature.feature_index, False))
            for item in positive_analyses
        ]
        if any(matched_by_sample) and not all(matched_by_sample):
            mixed_features.append(feature.label)
            mixed_samples.extend(
                item["name"]
                for item, matched in zip(positive_analyses, matched_by_sample)
                if not matched
            )
    if mixed_features:
        _add_finding(
            findings,
            _Finding(
                "OVER_SPECIFIC_CONTENT",
                "精确 content 只适配部分正向样本，对大小写、编码或等价载荷变化过于敏感。",
                "保留稳定的接口锚点，并将易变化的利用值改为 nocase、规范化 buffer 或受控模式。",
                sample_names=tuple(_unique(mixed_samples)),
                features=tuple(_unique(mixed_features)),
            ),
        )

    quality_warnings = " ".join(
        str(item) for item in validation.get("quality_warnings", [])
    ).casefold()
    structural_only = bool(features) and all(_is_structural_feature(feature) for feature in features)
    if structural_only or "weak_structural_only" in quality_warnings:
        _add_finding(
            findings,
            _Finding(
                "MISSING_EXPLOIT_VALUE",
                "规则只包含方法、接口路径或参数名，没有约束实际利用值。",
                "增加位于正确 buffer 的攻击值或攻击语义特征，同时保留稳定接口锚点。",
                features=tuple(feature.label for feature in features),
            ),
        )

    if failed_negative or int(validation.get("false_positive_count", 0) or 0) > 0:
        negative_matched_features = _unique(
            [
                feature
                for analysis in failed_negative
                for feature in analysis["matched_features"]
            ]
        )
        _add_finding(
            findings,
            _Finding(
                "FALSE_POSITIVE_WEAK_FEATURE",
                "近似负样本也满足当前特征组合，规则区分度不足。",
                "比较误报样本与正向样本，只增加攻击侧独有且稳定的特征；不要依赖 Host、长度或普通参数名。",
                sample_names=tuple(item["name"] for item in failed_negative),
                features=tuple(negative_matched_features),
            ),
        )

    if not findings and not bool(validation.get("passed", False)):
        _add_finding(
            findings,
            _Finding(
                "UNCLASSIFIED_FAILURE",
                "现有规则文本和样本证据不足以确定唯一失败原因。",
                "保留失败样本和 Suricata 输出，扩充确定性诊断后再进入修复循环。",
                sample_names=tuple(item["name"] for item in failed_analyses),
            ),
        )

    if findings:
        primary = findings[0]
        failure_type = primary.failure_type
        suspected_reason = primary.suspected_reason
        suggestion = primary.suggestion
    else:
        failure_type = "NONE"
        suspected_reason = "候选规则已通过当前样本矩阵，未发现确定性失败。"
        suggestion = "无需修复；继续保留规则及验证证据。"

    return {
        "failure_type": failure_type,
        "suspected_reason": suspected_reason,
        "suggestion": suggestion,
        "rule_direction": direction,
        "matched_features": _unique(matched_features),
        "unmatched_features": _unique(unmatched_features),
        "failed_samples": [_safe_public_analysis(item) for item in failed_analyses],
        "diagnostics": [finding.public_dict() for finding in findings],
        "parse_errors": parse_errors,
    }


__all__ = ["diagnose_candidate"]
