"""从原始 HTTP 证据构造可解释的正向与近似负样本矩阵。"""

from __future__ import annotations

import copy
import json
import re
import shutil
from dataclasses import dataclass, replace
from email import policy
from email.message import EmailMessage, Message
from email.parser import BytesParser
from pathlib import Path
from typing import Literal
from urllib.parse import quote, quote_plus, unquote, unquote_plus
from xml.etree import ElementTree

from suricata_agent.domain.rules.compiler import SemanticRequestChange, SemanticTestcase
from suricata_agent.domain.rules.knowledge import EXPLOIT_MARKERS, contains_exploit_marker

from .pcap import PcapConfig, generate_pcap, http_text_to_bytes


ExpectedOutcome = Literal["alert", "no_alert"]
SampleSource = Literal["original", "derived", "semantic", "uploaded"]
ValidationTarget = Literal[
    "generic",
    "request_detection",
    "response_detection",
    "transaction_specificity",
]
DerivedCase = tuple[str, ExpectedOutcome, str, bytes, bytes, int | None]


@dataclass(frozen=True, slots=True)
class MutationSkip:
    """一次未执行 body mutation 的结构化原因。"""

    code: str
    content_type: str
    detail: str

    def public_dict(self) -> dict[str, str]:
        return {
            "code": self.code,
            "content_type": self.content_type,
            "detail": self.detail,
        }


@dataclass(frozen=True, slots=True)
class TrafficDerivation:
    """派生样本以及未执行 mutation 的原因。"""

    cases: tuple[DerivedCase, ...]
    mutation_skips: tuple[MutationSkip, ...]

    @property
    def skips(self) -> tuple[MutationSkip, ...]:
        """提供简短别名，便于 API 消费方读取诊断。"""
        return self.mutation_skips


@dataclass(frozen=True, slots=True)
class TrafficSample:
    """一条可以独立回放并判断结果的流量样本。"""

    name: str
    expected: ExpectedOutcome
    reason: str
    source: SampleSource
    pcap_path: Path
    request: bytes | None = None
    response: bytes | None = None
    validates: ValidationTarget = "generic"

    def public_dict(self) -> dict[str, object]:
        """返回不包含完整报文和本机绝对路径的公开摘要。"""
        return {
            "name": self.name,
            "expected": self.expected,
            "reason": self.reason,
            "source": self.source,
            "validates": self.validates,
            "pcap_name": self.pcap_path.name,
            "request_line": _request_line(self.request) if self.request else None,
        }


class TrafficSampleList(list[TrafficSample]):
    """兼容 list 的样本集合，同时携带 body mutation 诊断。"""

    def __init__(
        self,
        values: list[TrafficSample],
        mutation_skips: tuple[MutationSkip, ...] = (),
    ) -> None:
        super().__init__(values)
        self.mutation_skips = mutation_skips

    @property
    def skips(self) -> tuple[MutationSkip, ...]:
        """返回构造样本时记录的 body mutation 诊断。"""
        return self.mutation_skips


def _semantic_skip(code: str, detail: str) -> MutationSkip:
    return MutationSkip(code, "semantic/testcase", detail)


@dataclass(frozen=True, slots=True)
class ParsedRequest:
    method: str
    target: str
    version: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def render(self) -> bytes:
        start_line = f"{self.method} {self.target} {self.version}"
        header_lines = [start_line, *(f"{name}: {value}" for name, value in self.headers)]
        return "\r\n".join(header_lines).encode("latin-1") + b"\r\n\r\n" + self.body


@dataclass(frozen=True, slots=True)
class ParsedResponse:
    version: str
    status_code: int
    reason: str
    headers: tuple[tuple[str, str], ...]
    body: bytes

    def render(self) -> bytes:
        status_line = f"{self.version} {self.status_code} {self.reason}".rstrip()
        header_lines = [status_line, *(f"{name}: {value}" for name, value in self.headers)]
        return "\r\n".join(header_lines).encode("latin-1") + b"\r\n\r\n" + self.body


@dataclass(frozen=True, slots=True)
class PasswdRecord:
    username: str
    password: str
    uid: str
    gid: str
    gecos: str
    home: str
    shell: str

    def render(self, *, shell: str | None = None) -> str:
        return ":".join(
            (
                self.username,
                self.password,
                self.uid,
                self.gid,
                self.gecos,
                self.home,
                self.shell if shell is None else shell,
            )
        )


@dataclass(frozen=True, slots=True)
class PasswdEvidence:
    records: tuple[PasswdRecord, ...]
    root: PasswdRecord
    encoding: str
    newline: str


@dataclass(frozen=True, slots=True)
class QueryPart:
    name: str
    value: str
    had_equals: bool = True

    def render(self) -> str:
        return f"{self.name}={self.value}" if self.had_equals else self.name


@dataclass(frozen=True, slots=True)
class AttackParameter:
    index: int
    name: str
    value: str
    kind: Literal["file_path", "generic"]


@dataclass(frozen=True, slots=True)
class JsonBodyField:
    path: tuple[str | int, ...]
    value: str
    kind: Literal["file_path", "generic"]


@dataclass(frozen=True, slots=True)
class XmlBodyField:
    path: tuple[int, ...]
    location: Literal["text", "attribute"]
    attribute: str | None
    name: str
    value: str
    kind: Literal["file_path", "generic"]


@dataclass(frozen=True, slots=True)
class MultipartBodyField:
    part_index: int
    name: str
    value: str
    charset: str
    kind: Literal["file_path", "generic"]


_HEADER_SEPARATOR_RE = re.compile(br"\r\n\r\n|\n\n|\r\r")
_XML_ENCODING_RE = re.compile(
    br"^\s*<\?xml[^>]*\bencoding\s*=\s*['\"]([A-Za-z0-9._-]+)['\"]",
    re.IGNORECASE,
)
_XML_DECLARATION_RE = re.compile(r"^\ufeff?\s*<\?xml[^>]*\?>", re.IGNORECASE)
_INVALID_PERCENT_ESCAPE_RE = re.compile(r"%(?![0-9A-Fa-f]{2})")
_SUSPICIOUS_FILE_RE = re.compile(
    r"(?:\.\.[/\\]|[a-zA-Z]:[/\\]|/etc/|win\.ini|passwd|%2e|%5c|%2f)",
    re.IGNORECASE,
)
_TEXTUAL_MEDIA_TYPES = {
    "application/graphql",
    "application/sql",
}
_XML_MEDIA_TYPES = {"application/xml", "text/xml"}
_MAX_STRUCTURED_BODY_BYTES = 1_048_576
_ATTACK_FIELD_NAMES = frozenset(
    {
        "cmd",
        "command",
        "code",
        "exec",
        "expression",
        "file",
        "filename",
        "path",
        "payload",
        "query",
        "script",
        "template",
        "url",
    }
)
_CASE_INSENSITIVE_MARKERS = (
    "whoami",
    "union select",
    "sleep(",
    "waitfor delay",
    "powershell",
    "cmd.exe",
    "<script",
)
_TRAILING_SPACE_MARKERS = (
    "whoami",
    "powershell",
    "cmd.exe",
    "sh -c",
    "bash -c",
)
_PASSWD_USERNAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]{0,63}\$?$")
_PASSWD_RESPONSE_MEDIA_TYPES = {
    "",
    "application/octet-stream",
    "application/pdf",
    "text/plain",
}
_COOKIE_HEADER_CONTINUATION_RE = re.compile(
    rb"(?i)^(?:samesite=(?:strict|lax|none)|secure|httponly)$"
)


def _message_bytes(message: str | bytes) -> bytes:
    return message if isinstance(message, bytes) else http_text_to_bytes(message)


def _response_message_bytes(message: str | bytes) -> bytes:
    """把文本响应转为字节，同时保留歧义头供诊断分支判断。"""
    if isinstance(message, bytes):
        return message
    raw = message.encode("utf-8")
    if _HEADER_SEPARATOR_RE.search(raw) is None:
        raw = raw.rstrip(b"\r\n") + b"\r\n\r\n"
    return raw


def _split_http_message(message: bytes) -> tuple[bytes, bytes]:
    match = _HEADER_SEPARATOR_RE.search(message)
    if match is None:
        raise ValueError("HTTP 报文缺少头体分隔符")
    return message[: match.start()], message[match.end() :]


def parse_http_request(message: str | bytes) -> ParsedRequest:
    """解析变体生成所需的请求行和头字段，同时保留 body 字节。"""
    raw = _message_bytes(message)
    header, body = _split_http_message(raw)
    lines = re.split(br"\r\n|\n|\r", header)
    if not lines or not lines[0]:
        raise ValueError("HTTP 请求缺少请求行")
    try:
        method, target, version = lines[0].decode("latin-1").split(" ", 2)
    except ValueError as exc:
        raise ValueError("HTTP 请求行格式无效") from exc

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[:1] in {b" ", b"\t"} and headers:
            name, previous = headers[-1]
            headers[-1] = (name, previous + " " + line.strip().decode("latin-1"))
            continue
        name, separator, value = line.partition(b":")
        if not separator:
            raise ValueError("HTTP 请求头字段格式无效")
        headers.append(
            (name.decode("latin-1").strip(), value.decode("latin-1").strip())
        )
    return ParsedRequest(method, target, version, tuple(headers), body)


def parse_http_response(message: str | bytes) -> ParsedResponse:
    """解析响应状态行、头字段与正文，供保守响应 mutation 使用。"""
    raw = _response_message_bytes(message)
    header, body = _split_http_message(raw)
    lines = re.split(br"\r\n|\n|\r", header)
    if not lines or not lines[0]:
        raise ValueError("HTTP 响应缺少状态行")
    parts = lines[0].decode("latin-1").split(" ", 2)
    if len(parts) < 2 or not parts[0].startswith("HTTP/"):
        raise ValueError("HTTP 响应状态行格式无效")
    try:
        status_code = int(parts[1], 10)
    except ValueError as exc:
        raise ValueError("HTTP 响应状态码无效") from exc
    if not 100 <= status_code <= 999 or str(status_code) != parts[1]:
        raise ValueError("HTTP 响应状态码必须是三位十进制整数")

    headers: list[tuple[str, str]] = []
    for line in lines[1:]:
        if not line:
            continue
        if line[:1] in {b" ", b"\t"} and headers:
            name, previous = headers[-1]
            headers[-1] = (name, previous + " " + line.strip().decode("latin-1"))
            continue
        name, separator, value = line.partition(b":")
        if not separator:
            if (
                headers
                and headers[-1][0].casefold() == "set-cookie"
                and _COOKIE_HEADER_CONTINUATION_RE.fullmatch(line.strip())
            ):
                previous_name, previous_value = headers[-1]
                headers[-1] = (
                    previous_name,
                    previous_value + "; " + line.strip().decode("latin-1"),
                )
                continue
            raise ValueError("HTTP 响应头字段格式无效")
        headers.append(
            (name.decode("latin-1").strip(), value.decode("latin-1").strip())
        )
    reason = parts[2] if len(parts) == 3 else ""
    return ParsedResponse(parts[0], status_code, reason, tuple(headers), body)


def _request_line(request: bytes | None) -> str | None:
    if request is None:
        return None
    first = re.split(br"\r\n|\n|\r", request, maxsplit=1)[0]
    return first.decode("latin-1", errors="replace")[:500]


def _split_target(target: str) -> tuple[str, list[QueryPart], str]:
    fragment = ""
    without_fragment = target
    if "#" in target:
        without_fragment, fragment = target.split("#", 1)
    path, marker, query = without_fragment.partition("?")
    parts: list[QueryPart] = []
    if marker:
        for raw_part in query.split("&"):
            name, equals, value = raw_part.partition("=")
            parts.append(QueryPart(name, value, bool(equals)))
    return path, parts, fragment


def _render_target(path: str, parts: list[QueryPart], fragment: str = "") -> str:
    target = path
    if parts:
        target += "?" + "&".join(part.render() for part in parts)
    if fragment:
        target += "#" + fragment
    return target


def _unique_name(existing: set[str], preferred: str) -> str:
    candidate = preferred
    while candidate.casefold() in existing:
        candidate = "_" + candidate
    return candidate


def _unique_parameter_name(parts: list[QueryPart], preferred: str) -> str:
    existing = {unquote_plus(part.name).casefold() for part in parts}
    return _unique_name(existing, preferred)


def _local_field_name(name: str) -> str:
    """去掉 XML namespace、数组后缀等表示差异，得到可比较字段名。"""
    local = name.rsplit("}", 1)[-1].rsplit(":", 1)[-1]
    return re.sub(r"\[\d+\]$", "", local).strip().casefold()


def _is_attack_field_name(name: str) -> bool:
    normalized = _local_field_name(name)
    return normalized in _ATTACK_FIELD_NAMES or any(
        normalized.endswith(candidate) for candidate in _ATTACK_FIELD_NAMES
    )


def _equivalent_case_variant(value: str) -> str | None:
    """只对已知大小写不敏感的攻击语义生成变体。"""
    for marker in _CASE_INSENSITIVE_MARKERS:
        match = re.search(re.escape(marker), value, flags=re.IGNORECASE)
        if match is None:
            continue
        changed = match.group(0).swapcase()
        if changed != match.group(0):
            return value[: match.start()] + changed + value[match.end() :]
    if re.search(r"(?i)\b[a-z]:[\\/]", value):
        changed = value.swapcase()
        return changed if changed != value else None
    return None


def _equivalent_trailing_space_variant(value: str) -> str | None:
    """命令型载荷末尾空白通常不改变 shell token，仅对明确命令标记启用。"""
    lowered = value.casefold()
    if value == value.rstrip() and any(
        marker in lowered for marker in _TRAILING_SPACE_MARKERS
    ):
        return value + " "
    return None


def _benign_body_value(kind: Literal["file_path", "generic"]) -> str:
    return "documents/report.pdf" if kind == "file_path" else "hello"


def _decoded_parameter_value(value: str, *, form: bool = False) -> str:
    return unquote_plus(value) if form else unquote(value)


def _looks_suspicious(value: str, *, form: bool = False) -> bool:
    decoded = _decoded_parameter_value(value, form=form)
    return (
        contains_exploit_marker(value)
        or contains_exploit_marker(decoded)
        or _SUSPICIOUS_FILE_RE.search(value) is not None
        or _SUSPICIOUS_FILE_RE.search(decoded) is not None
    )


def _attack_kind(value: str, *, form: bool = False) -> Literal["file_path", "generic"]:
    decoded = _decoded_parameter_value(value, form=form)
    if _SUSPICIOUS_FILE_RE.search(value) or _SUSPICIOUS_FILE_RE.search(decoded):
        return "file_path"
    return "generic"


def _find_attack_parameter(
    parts: list[QueryPart],
    *,
    form: bool = False,
) -> AttackParameter | None:
    if not parts:
        return None
    ranked = list(enumerate(parts))
    for require_marker, require_name in ((True, True), (False, True), (True, False)):
        for index, part in ranked:
            if not part.value:
                continue
            if require_name and not _is_attack_field_name(unquote_plus(part.name)):
                continue
            if require_marker and not _looks_suspicious(part.value, form=form):
                continue
            return AttackParameter(
                index,
                part.name,
                part.value,
                _attack_kind(part.value, form=form),
            )
    valued_parts = [
        (index, part)
        for index, part in enumerate(parts)
        if part.value
    ]
    if valued_parts:
        index, part = (
            max(
                valued_parts,
                key=lambda item: len(
                    _decoded_parameter_value(item[1].value, form=True)
                ),
            )
            if form
            else valued_parts[0]
        )
        return AttackParameter(index, part.name, part.value, "generic")
    return AttackParameter(0, parts[0].name, parts[0].value, "generic")


def _replace_query_value(
    parts: list[QueryPart],
    parameter: AttackParameter,
    value: str,
) -> list[QueryPart]:
    updated = list(parts)
    original = updated[parameter.index]
    updated[parameter.index] = QueryPart(original.name, value, True)
    return updated


def _set_header(
    headers: tuple[tuple[str, str], ...],
    name: str,
    value: str,
) -> tuple[tuple[str, str], ...]:
    updated: list[tuple[str, str]] = []
    replaced = False
    for current_name, current_value in headers:
        if current_name.lower() == name.lower():
            if not replaced:
                updated.append((current_name, value))
                replaced = True
        else:
            updated.append((current_name, current_value))
    if not replaced:
        updated.append((name, value))
    return tuple(updated)


def _header_values(
    headers: tuple[tuple[str, str], ...],
    name: str,
) -> list[str]:
    lowered = name.lower()
    return [value for current_name, value in headers if current_name.lower() == lowered]


def _media_type(headers: tuple[tuple[str, str], ...]) -> str:
    values = _header_values(headers, "Content-Type")
    if len(values) != 1:
        return ""
    return values[0].partition(";")[0].strip().lower()


def _declared_body_charset(
    headers: tuple[tuple[str, str], ...],
) -> str | None:
    values = _header_values(headers, "Content-Type")
    if len(values) != 1:
        return None
    match = re.search(
        r"(?:^|;)\s*charset\s*=\s*(?:\"([^\"]+)\"|'([^']+)'|([^;\s]+))",
        values[0],
        flags=re.IGNORECASE,
    )
    if match is None:
        return None
    return next(value for value in match.groups() if value).strip()


def _body_charset(headers: tuple[tuple[str, str], ...]) -> str:
    return _declared_body_charset(headers) or "utf-8"


def _body_rewrite_skip(parsed: ParsedRequest) -> MutationSkip | None:
    """返回阻止 body mutation 的协议层原因。"""
    content_type = _media_type(parsed.headers) or "unknown"
    if _header_values(parsed.headers, "Transfer-Encoding"):
        return MutationSkip(
            "TRANSFER_ENCODING_UNSUPPORTED",
            content_type,
            "Transfer-Encoding 报文不自动重写正文",
        )
    if len(_header_values(parsed.headers, "Content-Type")) > 1:
        return MutationSkip(
            "DUPLICATE_CONTENT_TYPE",
            content_type,
            "存在多个 Content-Type，无法确定正文格式",
        )
    content_encodings = {
        token.strip().lower()
        for value in _header_values(parsed.headers, "Content-Encoding")
        for token in value.split(",")
        if token.strip()
    }
    if content_encodings - {"identity"}:
        return MutationSkip(
            "CONTENT_ENCODING_UNSUPPORTED",
            content_type,
            "压缩或编码后的正文不自动改写",
        )
    content_lengths = _header_values(parsed.headers, "Content-Length")
    if len(content_lengths) > 1:
        return MutationSkip(
            "DUPLICATE_CONTENT_LENGTH",
            content_type,
            "存在多个 Content-Length，无法确定正文边界",
        )
    if content_lengths:
        try:
            declared_length = int(content_lengths[0], 10)
        except ValueError:
            return MutationSkip(
                "INVALID_CONTENT_LENGTH",
                content_type,
                "Content-Length 不是合法非负整数",
            )
        if declared_length < 0 or declared_length != len(parsed.body):
            return MutationSkip(
                "CONTENT_LENGTH_MISMATCH",
                content_type,
                "Content-Length 与实际正文字节数不一致",
            )
    return None


def _body_can_be_rewritten(parsed: ParsedRequest) -> bool:
    """仅改写边界明确的普通 HTTP 正文，保留兼容布尔入口。"""
    return _body_rewrite_skip(parsed) is None


def _replace_body(parsed: ParsedRequest, body: bytes) -> ParsedRequest:
    """替换正文并同步长度；正文变体始终生成可正常解析的 HTTP。"""
    headers = _set_header(parsed.headers, "Content-Length", str(len(body)))
    return replace(parsed, headers=headers, body=body)


def _response_rewrite_skip(parsed: ParsedResponse) -> MutationSkip | None:
    """返回阻止响应正文 mutation 的协议层或边界原因。"""
    content_type = _media_type(parsed.headers) or "unknown"
    if _header_values(parsed.headers, "Transfer-Encoding"):
        return MutationSkip(
            "RESPONSE_TRANSFER_ENCODING_UNSUPPORTED",
            content_type,
            "Transfer-Encoding 响应不自动重写正文",
        )
    if len(_header_values(parsed.headers, "Content-Type")) > 1:
        return MutationSkip(
            "RESPONSE_DUPLICATE_CONTENT_TYPE",
            content_type,
            "响应存在多个 Content-Type，无法确定正文格式",
        )
    content_encodings = {
        token.strip().lower()
        for value in _header_values(parsed.headers, "Content-Encoding")
        for token in value.split(",")
        if token.strip()
    }
    if content_encodings - {"identity"}:
        return MutationSkip(
            "RESPONSE_CONTENT_ENCODING_UNSUPPORTED",
            content_type,
            "压缩或编码后的响应正文不自动改写",
        )
    content_lengths = _header_values(parsed.headers, "Content-Length")
    if len(content_lengths) > 1:
        return MutationSkip(
            "RESPONSE_DUPLICATE_CONTENT_LENGTH",
            content_type,
            "响应存在多个 Content-Length，无法确定正文边界",
        )
    if content_lengths:
        value = content_lengths[0]
        if re.fullmatch(r"[0-9]+", value) is None:
            return MutationSkip(
                "RESPONSE_INVALID_CONTENT_LENGTH",
                content_type,
                "响应 Content-Length 不是合法非负十进制整数",
            )
        if int(value, 10) != len(parsed.body):
            return MutationSkip(
                "RESPONSE_CONTENT_LENGTH_MISMATCH",
                content_type,
                "响应 Content-Length 与实际正文字节数不一致",
            )
    if len(parsed.body) > _MAX_STRUCTURED_BODY_BYTES:
        return MutationSkip(
            "RESPONSE_BODY_TOO_LARGE",
            content_type,
            "响应正文超过自动 mutation 的大小上限",
        )
    return None


def _replace_response_body(parsed: ParsedResponse, body: bytes) -> ParsedResponse:
    headers = _set_header(parsed.headers, "Content-Length", str(len(body)))
    return replace(parsed, headers=headers, body=body)


def _simple_response(
    parsed: ParsedResponse,
    status_code: int,
    reason: str,
    body: bytes,
) -> bytes:
    response = ParsedResponse(
        version=parsed.version,
        status_code=status_code,
        reason=reason,
        headers=(
            ("Content-Type", "text/plain; charset=utf-8"),
            ("Content-Length", str(len(body))),
            ("Connection", "close"),
        ),
        body=body,
    )
    return response.render()


def _request_mentions_passwd(parsed: ParsedRequest) -> bool:
    candidates = [parsed.target, parsed.body.decode("latin-1", errors="ignore")]
    for candidate in candidates:
        decoded = candidate
        for _ in range(2):
            decoded_again = unquote_plus(decoded)
            if decoded_again == decoded:
                break
            decoded = decoded_again
        if "/etc/passwd" in decoded.replace("\\", "/").casefold():
            return True
    return False


def _parse_passwd_records(text: str) -> tuple[PasswdRecord, ...]:
    records: list[PasswdRecord] = []
    for raw_line in text.splitlines():
        line = raw_line.strip()
        fields = line.split(":")
        if len(fields) != 7:
            continue
        username, password, uid, gid, gecos, home, shell = fields
        if _PASSWD_USERNAME_RE.fullmatch(username) is None:
            continue
        if not uid.isdecimal() or not gid.isdecimal():
            continue
        if not home.startswith("/") or shell and not shell.startswith("/"):
            continue
        records.append(
            PasswdRecord(username, password, uid, gid, gecos, home, shell)
        )
    return tuple(records)


def _passwd_evidence(
    request: ParsedRequest,
    response: ParsedResponse,
) -> PasswdEvidence | None:
    media_type = _media_type(response.headers)
    if media_type not in _PASSWD_RESPONSE_MEDIA_TYPES:
        return None
    encoding = _body_charset(response.headers)
    try:
        text = response.body.decode(encoding)
    except (LookupError, UnicodeDecodeError):
        return None
    if "\x00" in text:
        return None
    records = _parse_passwd_records(text)
    roots = [
        record
        for record in records
        if record.username == "root"
        and record.uid == "0"
        and record.gid == "0"
        and record.home == "/root"
        and record.shell.startswith("/")
    ]
    if len(roots) != 1:
        return None
    if not _request_mentions_passwd(request) and len(records) < 2:
        return None
    newline = "\r\n" if "\r\n" in text else "\n"
    return PasswdEvidence(records, roots[0], encoding, newline)


def _encode_passwd_lines(
    evidence: PasswdEvidence,
    lines: list[str],
) -> bytes | None:
    return _encode_body(evidence.newline.join(lines) + evidence.newline, evidence.encoding)


def _response_case(
    name: str,
    expected: ExpectedOutcome,
    reason: str,
    parsed: ParsedResponse,
    body: bytes | None,
    *,
    mss: int | None = None,
) -> tuple[str, ExpectedOutcome, str, bytes, int | None] | None:
    if body is None or body == parsed.body:
        return None
    return name, expected, reason, _replace_response_body(parsed, body).render(), mss


def _derive_passwd_response_cases(
    parsed: ParsedResponse,
    evidence: PasswdEvidence,
) -> list[tuple[str, ExpectedOutcome, str, bytes, int | None]]:
    cases: list[tuple[str, ExpectedOutcome, str, bytes, int | None]] = []
    root_only = _response_case(
        "positive-response-passwd-root-only",
        "alert",
        "响应仅保留稳定的 root 账户语义",
        parsed,
        _encode_passwd_lines(evidence, [evidence.root.render()]),
    )
    if root_only:
        cases.append(root_only)

    changed_shell = "/bin/sh" if evidence.root.shell != "/bin/sh" else "/bin/bash"
    shell_case = _response_case(
        "positive-response-passwd-shell-changed",
        "alert",
        "root 登录 shell 变化但账户泄露语义保持不变",
        parsed,
        _encode_passwd_lines(
            evidence,
            [evidence.root.render(shell=changed_shell)],
        ),
    )
    if shell_case:
        cases.append(shell_case)

    if len(evidence.records) > 1:
        reordered_case = _response_case(
            "positive-response-passwd-lines-reordered",
            "alert",
            "账户记录顺序变化不影响 root 账户泄露证据",
            parsed,
            _encode_passwd_lines(
                evidence,
                [record.render() for record in reversed(evidence.records)],
            ),
        )
        if reordered_case:
            cases.append(reordered_case)

    usernames = {record.username for record in evidence.records}
    extra_username = "trafficcase"
    while extra_username in usernames:
        extra_username = "_" + extra_username
    extra_record = (
        f"{extra_username}:x:65530:65530:Service Account:"
        f"/nonexistent:/usr/sbin/nologin"
    )
    extra_case = _response_case(
        "positive-response-passwd-unrelated-account-added",
        "alert",
        "增加无关账户记录后 root 账户泄露证据仍然存在",
        parsed,
        _encode_passwd_lines(
            evidence,
            [*(record.render() for record in evidence.records), extra_record],
        ),
    )
    if extra_case:
        cases.append(extra_case)

    if len(parsed.body) > 17:
        cases.append(
            (
                "positive-response-passwd-segmented",
                "alert",
                "强响应证据跨多个 TCP 段传输",
                parsed.render(),
                17,
            )
        )

    cases.extend(
        (
            (
                "negative-response-passwd-error-page",
                "no_alert",
                "错误页提到目标文件，但不包含账户泄露证据",
                _simple_response(
                    parsed,
                    404,
                    "Not Found",
                    b"The requested file /etc/passwd was not found.\n",
                ),
                None,
            ),
            (
                "negative-response-passwd-fragment-decoy",
                "no_alert",
                "普通文本只包含 root 与 shell 单一片段",
                _simple_response(
                    parsed,
                    200,
                    "OK",
                    b"The root account commonly uses /bin/bash.\n",
                ),
                None,
            ),
            (
                "negative-response-passwd-documentation-decoy",
                "no_alert",
                "文档示例包含字段片段，但不是 passwd 文件内容",
                _simple_response(
                    parsed,
                    200,
                    "OK",
                    (
                        b"Documentation example only: "
                        b"root:x:0:0:<gecos>:<home>:<shell>\n"
                    ),
                ),
                None,
            ),
        )
    )
    return cases


def _derive_response_cases_with_diagnostic(
    request: ParsedRequest,
    response: bytes,
) -> tuple[
    list[tuple[str, ExpectedOutcome, str, bytes, int | None]],
    MutationSkip | None,
]:
    if not response:
        return [], None
    try:
        parsed = parse_http_response(response)
    except ValueError:
        return [], MutationSkip(
            "RESPONSE_PARSE_FAILED",
            "unknown",
            "HTTP 响应状态行、头字段或头体边界无效",
        )
    protocol_skip = _response_rewrite_skip(parsed)
    if protocol_skip is not None:
        return [], protocol_skip
    if not parsed.body:
        return [], None
    content_type = _media_type(parsed.headers) or "unknown"
    if not 200 <= parsed.status_code < 300:
        return [], MutationSkip(
            "RESPONSE_STATUS_UNSUPPORTED",
            content_type,
            "原始响应不是成功状态，不派生成功证据变体",
        )
    evidence = _passwd_evidence(request, parsed)
    if evidence is None:
        return [], MutationSkip(
            "RESPONSE_EVIDENCE_UNRECOGNIZED",
            content_type,
            "响应中没有可保守确认并改写的强成功证据",
        )
    return _derive_passwd_response_cases(parsed, evidence), None


def _decode_body(parsed: ParsedRequest) -> tuple[str, str] | None:
    encoding = _body_charset(parsed.headers)
    try:
        text = parsed.body.decode(encoding)
    except (LookupError, UnicodeDecodeError):
        return None
    if "\x00" in text:
        return None
    disallowed = sum(
        ord(character) < 32 and character not in "\r\n\t" for character in text
    )
    if disallowed > max(1, len(text) // 50):
        return None
    return text, encoding


def _encode_body(text: str, encoding: str) -> bytes | None:
    try:
        return text.encode(encoding)
    except (LookupError, UnicodeEncodeError):
        return None


def _iter_json_strings(
    value: object,
    path: tuple[str | int, ...] = (),
):
    if isinstance(value, str):
        yield path, value
        return
    if isinstance(value, dict):
        for key, nested in value.items():
            yield from _iter_json_strings(nested, (*path, key))
        return
    if isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _iter_json_strings(nested, (*path, index))


def _find_json_body_field(document: object) -> JsonBodyField | None:
    fields = [
        JsonBodyField(path, value, _attack_kind(value))
        for path, value in _iter_json_strings(document)
        if value
    ]
    for require_marker, require_name in ((True, True), (False, True), (True, False)):
        matching = [
            field
            for field in fields
            if (not require_marker or _looks_suspicious(field.value))
            and (
                not require_name
                or bool(field.path)
                and isinstance(field.path[-1], str)
                and _is_attack_field_name(field.path[-1])
            )
        ]
        if matching:
            return max(matching, key=lambda field: len(field.value))
    return max(fields, key=lambda field: len(field.value)) if fields else None


def _replace_json_path(
    document: object,
    path: tuple[str | int, ...],
    value: str,
) -> object:
    if not path:
        return value
    updated = copy.deepcopy(document)
    parent = updated
    for part in path[:-1]:
        parent = parent[part]  # type: ignore[index]
    parent[path[-1]] = value  # type: ignore[index]
    return updated


def _json_bytes(
    document: object,
    encoding: str,
    *,
    indent: int | None = None,
) -> bytes | None:
    separators = None if indent is not None else (",", ":")
    text = json.dumps(
        document,
        ensure_ascii=False,
        indent=indent,
        separators=separators,
    )
    return _encode_body(text, encoding)


def _escaped_json_string(value: str) -> str:
    chunks = ['"']
    for character in value:
        codepoint = ord(character)
        if codepoint <= 0xFFFF:
            chunks.append(f"\\u{codepoint:04x}")
            continue
        codepoint -= 0x10000
        high = 0xD800 + (codepoint >> 10)
        low = 0xDC00 + (codepoint & 0x3FF)
        chunks.append(f"\\u{high:04x}\\u{low:04x}")
    chunks.append('"')
    return "".join(chunks)


def _dump_json_with_escaped_path(
    value: object,
    target: tuple[str | int, ...],
    path: tuple[str | int, ...] = (),
) -> str:
    if path == target and isinstance(value, str):
        return _escaped_json_string(value)
    if isinstance(value, dict):
        members = (
            json.dumps(key, ensure_ascii=False)
            + ":"
            + _dump_json_with_escaped_path(nested, target, (*path, key))
            for key, nested in value.items()
        )
        return "{" + ",".join(members) + "}"
    if isinstance(value, list):
        members = (
            _dump_json_with_escaped_path(nested, target, (*path, index))
            for index, nested in enumerate(value)
        )
        return "[" + ",".join(members) + "]"
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def _parse_json_body(parsed: ParsedRequest) -> tuple[object, str] | None:
    if len(parsed.body) > _MAX_STRUCTURED_BODY_BYTES:
        return None
    decoded = _decode_body(parsed)
    if decoded is None:
        return None
    text, encoding = decoded
    media_type = _media_type(parsed.headers)
    stripped = text.lstrip()
    looks_like_json = stripped.startswith("{") or stripped.startswith("[")
    if not (media_type == "application/json" or media_type.endswith("+json")):
        if not looks_like_json:
            return None
    try:
        return json.loads(text), encoding
    except (TypeError, ValueError):
        return None


def _body_case(
    name: str,
    expected: ExpectedOutcome,
    reason: str,
    parsed: ParsedRequest,
    body: bytes | None,
) -> tuple[str, ExpectedOutcome, str, ParsedRequest] | None:
    if body is None or body == parsed.body:
        return None
    return name, expected, reason, _replace_body(parsed, body)


def _derive_json_body_cases(
    parsed: ParsedRequest,
    endpoint_path: str,
    query_parts: list[QueryPart],
    fragment: str,
) -> list[tuple[str, ExpectedOutcome, str, ParsedRequest]]:
    parsed_json = _parse_json_body(parsed)
    if parsed_json is None:
        return []
    document, encoding = parsed_json
    field = _find_json_body_field(document)
    if field is None:
        return []

    cases: list[tuple[str, ExpectedOutcome, str, ParsedRequest]] = []

    compact = _json_bytes(document, encoding)
    pretty = _json_bytes(document, encoding, indent=2)
    whitespace_body = pretty if compact == parsed.body.strip() else compact
    whitespace_case = _body_case(
        "positive-body-json-whitespace-changed",
        "alert",
        "JSON 空白与排版变化不改变攻击语义",
        parsed,
        whitespace_body,
    )
    if whitespace_case:
        cases.append(whitespace_case)

    if isinstance(document, dict) and len(document) > 1:
        reordered = dict(reversed(list(document.items())))
        reordered_case = _body_case(
            "positive-body-json-key-order-changed",
            "alert",
            "JSON 字段顺序变化不改变攻击语义",
            parsed,
            _json_bytes(reordered, encoding),
        )
        if reordered_case:
            cases.append(reordered_case)

    escaped_case = _body_case(
        "positive-body-json-value-encoded",
        "alert",
        "攻击字段使用等价的 JSON Unicode 转义",
        parsed,
        _encode_body(
            _dump_json_with_escaped_path(document, field.path),
            encoding,
        ),
    )
    if escaped_case:
        cases.append(escaped_case)

    case_variant = _equivalent_case_variant(field.value)
    if case_variant is not None:
        changed_case = _replace_json_path(document, field.path, case_variant)
        case_changed = _body_case(
            "positive-body-json-case-changed",
            "alert",
            "已知大小写不敏感的攻击语义使用另一种大小写表示",
            parsed,
            _json_bytes(changed_case, encoding),
        )
        if case_changed:
            cases.append(case_changed)

    trailing_variant = _equivalent_trailing_space_variant(field.value)
    if trailing_variant is not None:
        with_trailing_space = _replace_json_path(
            document,
            field.path,
            trailing_variant,
        )
        trailing_space_case = _body_case(
            "positive-body-json-trailing-space",
            "alert",
            "命令型攻击值末尾增加不改变 shell token 的空白",
            parsed,
            _json_bytes(with_trailing_space, encoding),
        )
        if trailing_space_case:
            cases.append(trailing_space_case)

    if isinstance(document, dict):
        extra_key = "_traffic_variant"
        while extra_key in document:
            extra_key = "_" + extra_key
        with_extra = copy.deepcopy(document)
        with_extra[extra_key] = "1"
        extra_case = _body_case(
            "positive-body-json-extra-field",
            "alert",
            "增加无关 JSON 字段后攻击语义保持不变",
            parsed,
            _json_bytes(with_extra, encoding),
        )
        if extra_case:
            cases.append(extra_case)

    empty_document = _replace_json_path(document, field.path, "")
    empty_case = _body_case(
        "negative-body-json-empty-value",
        "no_alert",
        "相同接口和 JSON 字段，但目标字段为空",
        parsed,
        _json_bytes(empty_document, encoding),
    )
    if empty_case:
        cases.append(empty_case)

    benign_value = _benign_body_value(field.kind)
    benign_document = _replace_json_path(document, field.path, benign_value)
    benign_case = _body_case(
        "negative-body-json-benign-value",
        "no_alert",
        "相同接口和 JSON 字段，但字段值不包含攻击内容",
        parsed,
        _json_bytes(benign_document, encoding),
    )
    if benign_case:
        cases.append(benign_case)

    if isinstance(benign_document, dict):
        note_key = "description"
        while note_key in benign_document:
            note_key = "_" + note_key
        same_value_elsewhere = copy.deepcopy(benign_document)
        same_value_elsewhere[note_key] = field.value
        moved_case = _body_case(
            "negative-body-json-value-in-other-field",
            "no_alert",
            "攻击字符串只出现在无关 description 字段中",
            parsed,
            _json_bytes(same_value_elsewhere, encoding),
        )
        if moved_case:
            cases.append(moved_case)

    if endpoint_path != "/not-vulnerable":
        cases.append(
            (
                "negative-body-json-different-endpoint",
                "no_alert",
                "相同 JSON 攻击值位于其他接口，不属于当前漏洞入口",
                replace(
                    parsed,
                    target=_render_target("/not-vulnerable", query_parts, fragment),
                ),
            )
        )
    return cases


def _parse_form_body(
    parsed: ParsedRequest,
) -> tuple[list[QueryPart], str] | None:
    if _media_type(parsed.headers) != "application/x-www-form-urlencoded":
        return None
    if len(parsed.body) > _MAX_STRUCTURED_BODY_BYTES:
        return None
    decoded = _decode_body(parsed)
    if decoded is None:
        return None
    text, encoding = decoded
    if _INVALID_PERCENT_ESCAPE_RE.search(text):
        return None
    parts: list[QueryPart] = []
    for raw_part in text.split("&"):
        name, equals, value = raw_part.partition("=")
        parts.append(QueryPart(name, value, bool(equals)))
    return parts, encoding


def _form_body(parts: list[QueryPart], encoding: str) -> bytes | None:
    return _encode_body("&".join(part.render() for part in parts), encoding)


def _derive_form_body_cases(
    parsed: ParsedRequest,
    endpoint_path: str,
    query_parts: list[QueryPart],
    fragment: str,
) -> list[tuple[str, ExpectedOutcome, str, ParsedRequest]]:
    parsed_form = _parse_form_body(parsed)
    if parsed_form is None:
        return []
    parts, encoding = parsed_form
    if not any(part.value for part in parts):
        return []
    attack = _find_attack_parameter(parts, form=True)
    if attack is None:
        return []

    cases: list[tuple[str, ExpectedOutcome, str, ParsedRequest]] = []
    extra_name = _unique_parameter_name(parts, "trace")
    extra_case = _body_case(
        "positive-body-form-extra-parameter",
        "alert",
        "增加无关表单参数后攻击语义保持不变",
        parsed,
        _form_body([*parts, QueryPart(extra_name, "1")], encoding),
    )
    if extra_case:
        cases.append(extra_case)

    if len(parts) > 1:
        order_case = _body_case(
            "positive-body-form-parameter-order-changed",
            "alert",
            "表单参数顺序变化但攻击字段保持不变",
            parsed,
            _form_body(list(reversed(parts)), encoding),
        )
        if order_case:
            cases.append(order_case)

    decoded_attack = unquote_plus(attack.value)
    encoded_attack = quote_plus(decoded_attack, safe="")
    encoded_case = _body_case(
        "positive-body-form-url-encoded",
        "alert",
        "攻击字段使用等价的表单 URL 编码",
        parsed,
        _form_body(
            _replace_query_value(parts, attack, encoded_attack),
            encoding,
        ),
    )
    if encoded_case:
        cases.append(encoded_case)

    case_variant = _equivalent_case_variant(decoded_attack)
    if case_variant is not None:
        case_changed = _body_case(
            "positive-body-form-case-changed",
            "alert",
            "已知大小写不敏感的表单攻击值使用另一种大小写表示",
            parsed,
            _form_body(
                _replace_query_value(
                    parts,
                    attack,
                    quote_plus(case_variant, safe=""),
                ),
                encoding,
            ),
        )
        if case_changed:
            cases.append(case_changed)

    trailing_variant = _equivalent_trailing_space_variant(decoded_attack)
    if trailing_variant is not None:
        trailing_space_case = _body_case(
            "positive-body-form-trailing-space",
            "alert",
            "命令型表单攻击值末尾增加不改变 shell token 的空白",
            parsed,
            _form_body(
                _replace_query_value(
                    parts,
                    attack,
                    quote_plus(trailing_variant, safe=""),
                ),
                encoding,
            ),
        )
        if trailing_space_case:
            cases.append(trailing_space_case)

    empty_case = _body_case(
        "negative-body-form-empty-value",
        "no_alert",
        "相同接口和表单字段，但目标字段为空",
        parsed,
        _form_body(_replace_query_value(parts, attack, ""), encoding),
    )
    if empty_case:
        cases.append(empty_case)

    benign_value = quote_plus(_benign_body_value(attack.kind), safe="")
    benign_parts = _replace_query_value(parts, attack, benign_value)
    benign_case = _body_case(
        "negative-body-form-benign-value",
        "no_alert",
        "相同接口和表单参数名，但参数值不包含攻击内容",
        parsed,
        _form_body(benign_parts, encoding),
    )
    if benign_case:
        cases.append(benign_case)

    description_name = _unique_parameter_name(benign_parts, "description")
    moved_case = _body_case(
        "negative-body-form-value-in-other-parameter",
        "no_alert",
        "攻击字符串只出现在无关表单参数中",
        parsed,
        _form_body(
            [
                *benign_parts,
                QueryPart(description_name, quote_plus(decoded_attack, safe="")),
            ],
            encoding,
        ),
    )
    if moved_case:
        cases.append(moved_case)

    if endpoint_path != "/not-vulnerable":
        cases.append(
            (
                "negative-body-form-different-endpoint",
                "no_alert",
                "相同表单攻击值位于其他接口，不属于当前漏洞入口",
                replace(
                    parsed,
                    target=_render_target("/not-vulnerable", query_parts, fragment),
                ),
            )
        )
    return cases


def _parse_multipart_body(
    parsed: ParsedRequest,
) -> tuple[Message, list[MultipartBodyField]] | None:
    if _media_type(parsed.headers) != "multipart/form-data":
        return None
    if len(parsed.body) > _MAX_STRUCTURED_BODY_BYTES:
        return None
    content_types = _header_values(parsed.headers, "Content-Type")
    if len(content_types) != 1:
        return None
    envelope = (
        f"Content-Type: {content_types[0]}\r\nMIME-Version: 1.0\r\n\r\n".encode(
            "latin-1"
        )
        + parsed.body
    )
    try:
        message = BytesParser(policy=policy.HTTP).parsebytes(envelope)
    except (TypeError, ValueError):
        return None
    payload = message.get_payload()
    if message.defects or not message.is_multipart() or not isinstance(payload, list):
        return None

    fields: list[MultipartBodyField] = []
    for index, part in enumerate(payload):
        if not isinstance(part, Message) or part.is_multipart():
            continue
        if part.get_filename() is not None:
            continue
        name = part.get_param("name", header="content-disposition")
        if not isinstance(name, str) or not name:
            continue
        raw_value = part.get_payload(decode=True)
        if raw_value is None:
            plain_value = part.get_payload()
            if not isinstance(plain_value, str):
                continue
            raw_value = plain_value.encode("latin-1", errors="replace")
        charset = part.get_content_charset() or "utf-8"
        try:
            value = raw_value.decode(charset)
        except (LookupError, UnicodeDecodeError):
            continue
        if not value or "\x00" in value:
            continue
        fields.append(
            MultipartBodyField(
                part_index=index,
                name=name,
                value=value,
                charset=charset,
                kind=_attack_kind(value),
            )
        )
    return message, fields


def _find_multipart_body_field(
    fields: list[MultipartBodyField],
) -> MultipartBodyField:
    for require_marker, require_name in ((True, True), (False, True), (True, False)):
        matching = [
            field
            for field in fields
            if (not require_marker or _looks_suspicious(field.value))
            and (not require_name or _is_attack_field_name(field.name))
        ]
        if matching:
            return max(matching, key=lambda field: len(field.value))
    return max(fields, key=lambda field: len(field.value))


def _set_multipart_field(
    message: Message,
    field: MultipartBodyField,
    value: str,
) -> None:
    payload = message.get_payload()
    if not isinstance(payload, list):
        raise ValueError("multipart payload 必须是 part 数组")
    part = payload[field.part_index]
    if not isinstance(part, Message):
        raise ValueError("multipart part 类型无效")
    while part.get("Content-Transfer-Encoding") is not None:
        del part["Content-Transfer-Encoding"]
    part.set_payload(value.encode(field.charset))


def _new_multipart_field(name: str, value: str, charset: str = "utf-8") -> Message:
    part = EmailMessage(policy=policy.HTTP)
    part["Content-Disposition"] = f'form-data; name="{name}"'
    part["Content-Type"] = f"text/plain; charset={charset}"
    part.set_payload(value.encode(charset))
    return part


def _multipart_field_names(message: Message) -> set[str]:
    payload = message.get_payload()
    if not isinstance(payload, list):
        return set()
    return {
        str(name).casefold()
        for part in payload
        if isinstance(part, Message)
        for name in [part.get_param("name", header="content-disposition")]
        if name is not None
    }


def _serialize_multipart(message: Message) -> bytes | None:
    try:
        rendered = message.as_bytes(policy=policy.HTTP)
    except (LookupError, TypeError, UnicodeError, ValueError):
        return None
    separator = _HEADER_SEPARATOR_RE.search(rendered)
    return rendered[separator.end() :] if separator is not None else None


def _multipart_case(
    name: str,
    expected: ExpectedOutcome,
    reason: str,
    parsed: ParsedRequest,
    message: Message,
) -> tuple[str, ExpectedOutcome, str, ParsedRequest] | None:
    body = _serialize_multipart(message)
    content_type = message.get("Content-Type")
    if body is None or content_type is None:
        return None
    headers = _set_header(parsed.headers, "Content-Type", str(content_type))
    variant = _replace_body(replace(parsed, headers=headers), body)
    if variant.body == parsed.body and variant.headers == parsed.headers:
        return None
    return name, expected, reason, variant


def _derive_multipart_body_cases(
    parsed: ParsedRequest,
    endpoint_path: str,
    query_parts: list[QueryPart],
    fragment: str,
) -> list[tuple[str, ExpectedOutcome, str, ParsedRequest]]:
    parsed_multipart = _parse_multipart_body(parsed)
    if parsed_multipart is None:
        return []
    message, fields = parsed_multipart
    if not fields:
        return []
    field = _find_multipart_body_field(fields)
    cases: list[tuple[str, ExpectedOutcome, str, ParsedRequest]] = []

    boundary_changed = copy.deepcopy(message)
    boundary = "----traffic-case-boundary"
    while boundary.encode("ascii") in parsed.body:
        boundary += "x"
    boundary_changed.set_boundary(boundary)
    boundary_case = _multipart_case(
        "positive-body-multipart-boundary-changed",
        "alert",
        "multipart boundary 变化不改变表单字段语义",
        parsed,
        boundary_changed,
    )
    if boundary_case:
        cases.append(boundary_case)

    payload = message.get_payload()
    if isinstance(payload, list) and len(payload) > 1:
        part_names = [
            part.get_param("name", header="content-disposition")
            if isinstance(part, Message)
            else None
            for part in payload
        ]
        if all(isinstance(name, str) for name in part_names) and len(part_names) == len(
            set(part_names)
        ):
            reordered = copy.deepcopy(message)
            reordered.set_payload(list(reversed(reordered.get_payload())))
            reordered_case = _multipart_case(
                "positive-body-multipart-field-order-changed",
                "alert",
                "名称唯一的 multipart 字段顺序变化不改变表单语义",
                parsed,
                reordered,
            )
            if reordered_case:
                cases.append(reordered_case)

    with_extra = copy.deepcopy(message)
    extra_name = _unique_name(_multipart_field_names(with_extra), "trace")
    with_extra.attach(_new_multipart_field(extra_name, "1"))
    extra_case = _multipart_case(
        "positive-body-multipart-extra-field",
        "alert",
        "增加无关 multipart 字段后攻击语义保持不变",
        parsed,
        with_extra,
    )
    if extra_case:
        cases.append(extra_case)

    for suffix, reason, changed_value in (
        (
            "case-changed",
            "已知大小写不敏感的 multipart 攻击值使用另一种大小写表示",
            _equivalent_case_variant(field.value),
        ),
        (
            "trailing-space",
            "命令型 multipart 攻击值末尾增加不改变 shell token 的空白",
            _equivalent_trailing_space_variant(field.value),
        ),
    ):
        if changed_value is None:
            continue
        changed = copy.deepcopy(message)
        _set_multipart_field(changed, field, changed_value)
        changed_case = _multipart_case(
            f"positive-body-multipart-{suffix}",
            "alert",
            reason,
            parsed,
            changed,
        )
        if changed_case:
            cases.append(changed_case)

    for suffix, reason, replacement_value in (
        ("empty-value", "相同 multipart 字段为空", ""),
        (
            "benign-value",
            "相同 multipart 字段只包含普通值",
            _benign_body_value(field.kind),
        ),
    ):
        changed = copy.deepcopy(message)
        _set_multipart_field(changed, field, replacement_value)
        changed_case = _multipart_case(
            f"negative-body-multipart-{suffix}",
            "no_alert",
            reason,
            parsed,
            changed,
        )
        if changed_case:
            cases.append(changed_case)

    moved = copy.deepcopy(message)
    _set_multipart_field(moved, field, _benign_body_value(field.kind))
    description_name = _unique_name(
        _multipart_field_names(moved),
        "description",
    )
    moved.attach(_new_multipart_field(description_name, field.value, field.charset))
    moved_case = _multipart_case(
        "negative-body-multipart-value-in-description",
        "no_alert",
        "攻击字符串只出现在无关 description part，目标字段为普通值",
        parsed,
        moved,
    )
    if moved_case:
        cases.append(moved_case)

    if endpoint_path != "/not-vulnerable":
        cases.append(
            (
                "negative-body-multipart-different-endpoint",
                "no_alert",
                "相同 multipart 攻击值位于其他接口",
                replace(
                    parsed,
                    target=_render_target("/not-vulnerable", query_parts, fragment),
                ),
            )
        )
    return cases


def _xml_element_at(root: ElementTree.Element, path: tuple[int, ...]) -> ElementTree.Element:
    current = root
    for index in path:
        current = list(current)[index]
    return current


def _iter_xml_fields(
    element: ElementTree.Element,
    path: tuple[int, ...] = (),
):
    name = _local_field_name(str(element.tag))
    if element.text and element.text.strip():
        value = element.text.strip()
        yield XmlBodyField(path, "text", None, name, value, _attack_kind(value))
    for attribute, raw_value in element.attrib.items():
        if raw_value.strip():
            value = raw_value.strip()
            yield XmlBodyField(
                path,
                "attribute",
                attribute,
                _local_field_name(attribute),
                value,
                _attack_kind(value),
            )
    for index, child in enumerate(list(element)):
        yield from _iter_xml_fields(child, (*path, index))


def _find_xml_body_field(fields: list[XmlBodyField]) -> XmlBodyField:
    for require_marker, require_name in ((True, True), (False, True), (True, False)):
        matching = [
            field
            for field in fields
            if (not require_marker or _looks_suspicious(field.value))
            and (not require_name or _is_attack_field_name(field.name))
        ]
        if matching:
            return max(matching, key=lambda field: len(field.value))
    return max(fields, key=lambda field: len(field.value))


def _set_xml_field(
    root: ElementTree.Element,
    field: XmlBodyField,
    value: str,
) -> None:
    element = _xml_element_at(root, field.path)
    if field.location == "attribute":
        assert field.attribute is not None
        original = element.get(field.attribute, "")
        element.set(field.attribute, original.replace(field.value, value, 1))
        return
    original = element.text or ""
    element.text = original.replace(field.value, value, 1)


def _serialize_xml(root: ElementTree.Element, encoding: str) -> bytes | None:
    try:
        return ElementTree.tostring(root, encoding=encoding, short_empty_elements=True)
    except (LookupError, TypeError, UnicodeError, ValueError):
        return None


def _xml_body_encoding(parsed: ParsedRequest) -> str:
    declared = _declared_body_charset(parsed.headers)
    if declared:
        return declared
    body = parsed.body
    if body.startswith((b"\xff\xfe\x00\x00", b"\x00\x00\xfe\xff")):
        return "utf-32"
    if body.startswith((b"\xff\xfe", b"\xfe\xff")):
        return "utf-16"
    if body.startswith(b"\x00<\x00?"):
        return "utf-16-be"
    if body.startswith(b"<\x00?\x00"):
        return "utf-16-le"
    match = _XML_ENCODING_RE.search(body[:512])
    if match is not None:
        return match.group(1).decode("ascii")
    return "utf-8"


def _parse_xml_body(
    parsed: ParsedRequest,
) -> tuple[ElementTree.Element, str, list[XmlBodyField]] | None:
    media_type = _media_type(parsed.headers)
    if media_type not in _XML_MEDIA_TYPES and not media_type.endswith("+xml"):
        return None
    if len(parsed.body) > _MAX_STRUCTURED_BODY_BYTES:
        return None
    encoding = _xml_body_encoding(parsed)
    try:
        text = parsed.body.decode(encoding)
    except (LookupError, UnicodeDecodeError):
        return None
    if re.search(r"<!\s*(?:DOCTYPE|ENTITY)\b", text, flags=re.IGNORECASE):
        return None
    parse_text = _XML_DECLARATION_RE.sub("", text, count=1)
    if "<?" in parse_text:
        return None
    try:
        root = ElementTree.fromstring(parse_text)
    except (ElementTree.ParseError, ValueError):
        return None
    fields = list(_iter_xml_fields(root))
    return (root, encoding, fields) if fields else None


def _derive_xml_body_cases(
    parsed: ParsedRequest,
    endpoint_path: str,
    query_parts: list[QueryPart],
    fragment: str,
) -> list[tuple[str, ExpectedOutcome, str, ParsedRequest]]:
    parsed_xml = _parse_xml_body(parsed)
    if parsed_xml is None:
        return []
    root, encoding, fields = parsed_xml
    field = _find_xml_body_field(fields)
    cases: list[tuple[str, ExpectedOutcome, str, ParsedRequest]] = []

    reordered = copy.deepcopy(root)
    reordered_any = False
    for element in reordered.iter():
        if len(element.attrib) > 1:
            attributes = list(element.attrib.items())
            element.attrib.clear()
            element.attrib.update(reversed(attributes))
            reordered_any = True
            break
    if reordered_any:
        reordered_case = _body_case(
            "positive-body-xml-attribute-order-changed",
            "alert",
            "XML 属性顺序变化不改变文档语义",
            parsed,
            _serialize_xml(reordered, encoding),
        )
        if reordered_case:
            cases.append(reordered_case)

    numeric_root = copy.deepcopy(root)
    sentinel = "TRAFFIC_VARIANT_TARGET_7F3A"
    while sentinel in field.value:
        sentinel += "X"
    _set_xml_field(numeric_root, field, sentinel)
    try:
        numeric_text = ElementTree.tostring(numeric_root, encoding="unicode")
        character_refs = "".join(f"&#x{ord(character):X};" for character in field.value)
        numeric_body = _encode_body(
            numeric_text.replace(sentinel, character_refs, 1),
            encoding,
        )
    except (TypeError, ValueError):
        numeric_body = None
    numeric_case = _body_case(
        "positive-body-xml-character-reference",
        "alert",
        "XML 字符引用与原始攻击字段值语义等价",
        parsed,
        numeric_body,
    )
    if numeric_case:
        cases.append(numeric_case)

    with_comment = copy.deepcopy(root)
    with_comment.insert(0, ElementTree.Comment("traffic-variant"))
    comment_case = _body_case(
        "positive-body-xml-comment-added",
        "alert",
        "增加 XML 注释不改变业务字段语义",
        parsed,
        _serialize_xml(with_comment, encoding),
    )
    if comment_case:
        cases.append(comment_case)

    for suffix, reason, changed_value in (
        (
            "case-changed",
            "已知大小写不敏感的 XML 攻击值使用另一种大小写表示",
            _equivalent_case_variant(field.value),
        ),
        (
            "trailing-space",
            "命令型 XML 攻击值末尾增加不改变 shell token 的空白",
            _equivalent_trailing_space_variant(field.value),
        ),
    ):
        if changed_value is None:
            continue
        changed = copy.deepcopy(root)
        _set_xml_field(changed, field, changed_value)
        changed_case = _body_case(
            f"positive-body-xml-{suffix}",
            "alert",
            reason,
            parsed,
            _serialize_xml(changed, encoding),
        )
        if changed_case:
            cases.append(changed_case)

    for suffix, reason, replacement_value in (
        ("empty-value", "相同 XML 字段为空", ""),
        (
            "benign-value",
            "相同 XML 字段只包含普通值",
            _benign_body_value(field.kind),
        ),
    ):
        changed = copy.deepcopy(root)
        _set_xml_field(changed, field, replacement_value)
        changed_case = _body_case(
            f"negative-body-xml-{suffix}",
            "no_alert",
            reason,
            parsed,
            _serialize_xml(changed, encoding),
        )
        if changed_case:
            cases.append(changed_case)

    if "--" not in field.value and not field.value.endswith("-"):
        moved = copy.deepcopy(root)
        _set_xml_field(moved, field, _benign_body_value(field.kind))
        moved.append(ElementTree.Comment(field.value))
        moved_case = _body_case(
            "negative-body-xml-value-in-comment",
            "no_alert",
            "攻击字符串只出现在 XML 注释，目标字段为普通值",
            parsed,
            _serialize_xml(moved, encoding),
        )
        if moved_case:
            cases.append(moved_case)

    if endpoint_path != "/not-vulnerable":
        cases.append(
            (
                "negative-body-xml-different-endpoint",
                "no_alert",
                "相同 XML 攻击值位于其他接口",
                replace(
                    parsed,
                    target=_render_target("/not-vulnerable", query_parts, fragment),
                ),
            )
        )
    return cases


def _is_text_body(parsed: ParsedRequest) -> bool:
    media_type = _media_type(parsed.headers)
    if media_type.startswith("text/"):
        return True
    if (
        media_type in _TEXTUAL_MEDIA_TYPES
        or media_type in _XML_MEDIA_TYPES
        or media_type.endswith("+xml")
    ):
        return True
    return not media_type


def _matching_exploit_marker(text: str) -> str | None:
    lowered = text.lower()
    matches = [
        marker
        for marker in EXPLOIT_MARKERS
        if marker and marker.lower() in lowered
    ]
    return max(matches, key=len) if matches else None


def _derive_text_body_cases(
    parsed: ParsedRequest,
    endpoint_path: str,
    query_parts: list[QueryPart],
    fragment: str,
) -> list[tuple[str, ExpectedOutcome, str, ParsedRequest]]:
    if not _is_text_body(parsed):
        return []
    decoded = _decode_body(parsed)
    if decoded is None:
        return []
    text, encoding = decoded
    marker = _matching_exploit_marker(text)
    if marker is None:
        return []

    cases: list[tuple[str, ExpectedOutcome, str, ParsedRequest]] = []
    if "\r\n" in text:
        changed_newlines = text.replace("\r\n", "\n")
    elif "\n" in text:
        changed_newlines = text.replace("\n", "\r\n")
    else:
        changed_newlines = text
    newline_case = _body_case(
        "positive-body-text-line-endings-changed",
        "alert",
        "文本正文换行格式变化不改变攻击内容",
        parsed,
        _encode_body(changed_newlines, encoding),
    )
    if newline_case:
        cases.append(newline_case)

    neutralized = text
    for current_marker in sorted(EXPLOIT_MARKERS, key=len, reverse=True):
        if current_marker:
            neutralized = re.sub(
                re.escape(current_marker),
                "safe-value",
                neutralized,
                flags=re.IGNORECASE,
            )
    benign_case = _body_case(
        "negative-body-text-marker-removed",
        "no_alert",
        "相同接口和文本结构，但正文不再包含攻击标记",
        parsed,
        _encode_body(neutralized, encoding),
    )
    if benign_case:
        cases.append(benign_case)

    if endpoint_path != "/not-vulnerable":
        cases.append(
            (
                "negative-body-text-different-endpoint",
                "no_alert",
                "相同文本攻击内容位于其他接口，不属于当前漏洞入口",
                replace(
                    parsed,
                    target=_render_target("/not-vulnerable", query_parts, fragment),
                ),
            )
        )
    return cases


def _format_skip(parsed: ParsedRequest, code: str, detail: str) -> MutationSkip:
    return MutationSkip(code, _media_type(parsed.headers) or "unknown", detail)


def _json_failure_skip(parsed: ParsedRequest) -> MutationSkip:
    if len(parsed.body) > _MAX_STRUCTURED_BODY_BYTES:
        return _format_skip(
            parsed,
            "JSON_BODY_TOO_LARGE",
            "JSON 正文超过自动 mutation 的大小上限",
        )
    decoded = _decode_body(parsed)
    if decoded is None:
        return _format_skip(
            parsed,
            "JSON_DECODE_FAILED",
            "JSON 正文无法按声明字符集安全解码",
        )
    text, _encoding = decoded
    try:
        document = json.loads(text)
    except (TypeError, ValueError):
        return _format_skip(parsed, "JSON_PARSE_FAILED", "JSON 正文语法无效")
    if _find_json_body_field(document) is None:
        return _format_skip(
            parsed,
            "JSON_NO_MUTABLE_FIELD",
            "JSON 中没有可用于构造语义变体的字符串字段",
        )
    return _format_skip(
        parsed,
        "JSON_MUTATION_UNAVAILABLE",
        "JSON 解析成功，但没有生成与原文不同的安全变体",
    )


def _form_failure_skip(parsed: ParsedRequest) -> MutationSkip:
    if len(parsed.body) > _MAX_STRUCTURED_BODY_BYTES:
        return _format_skip(
            parsed,
            "FORM_BODY_TOO_LARGE",
            "表单正文超过自动 mutation 的大小上限",
        )
    decoded = _decode_body(parsed)
    if decoded is None:
        return _format_skip(
            parsed,
            "FORM_DECODE_FAILED",
            "表单正文无法按声明字符集安全解码",
        )
    text, _encoding = decoded
    if _INVALID_PERCENT_ESCAPE_RE.search(text):
        return _format_skip(
            parsed,
            "FORM_PARSE_FAILED",
            "表单正文包含不完整的百分号编码",
        )
    parsed_form = _parse_form_body(parsed)
    if parsed_form is None or not any(part.value for part in parsed_form[0]):
        return _format_skip(
            parsed,
            "FORM_NO_MUTABLE_FIELD",
            "表单中没有带值的可变字段",
        )
    return _format_skip(
        parsed,
        "FORM_MUTATION_UNAVAILABLE",
        "表单解析成功，但没有生成与原文不同的安全变体",
    )


def _multipart_boundary(parsed: ParsedRequest) -> str | None:
    values = _header_values(parsed.headers, "Content-Type")
    if len(values) != 1:
        return None
    header = EmailMessage(policy=policy.HTTP)
    try:
        header["Content-Type"] = values[0]
    except (TypeError, ValueError):
        return None
    return header.get_boundary()


def _multipart_failure_skip(parsed: ParsedRequest) -> MutationSkip:
    if len(parsed.body) > _MAX_STRUCTURED_BODY_BYTES:
        return _format_skip(
            parsed,
            "MULTIPART_BODY_TOO_LARGE",
            "multipart 正文超过自动 mutation 的大小上限",
        )
    if not _multipart_boundary(parsed):
        return _format_skip(
            parsed,
            "MULTIPART_BOUNDARY_MISSING",
            "multipart/form-data 缺少有效 boundary 参数",
        )
    parsed_multipart = _parse_multipart_body(parsed)
    if parsed_multipart is None:
        return _format_skip(
            parsed,
            "MULTIPART_PARSE_FAILED",
            "multipart 正文与声明的 boundary 不匹配或结构无效",
        )
    _message, fields = parsed_multipart
    if not fields:
        return _format_skip(
            parsed,
            "MULTIPART_NO_MUTABLE_FIELD",
            "multipart 中没有可安全改写的普通文本字段",
        )
    return _format_skip(
        parsed,
        "MULTIPART_MUTATION_UNAVAILABLE",
        "multipart 解析成功，但没有生成与原文不同的安全变体",
    )


def _xml_failure_skip(parsed: ParsedRequest) -> MutationSkip:
    if len(parsed.body) > _MAX_STRUCTURED_BODY_BYTES:
        return _format_skip(
            parsed,
            "XML_BODY_TOO_LARGE",
            "XML 正文超过自动 mutation 的大小上限",
        )
    encoding = _xml_body_encoding(parsed)
    try:
        text = parsed.body.decode(encoding)
    except (LookupError, UnicodeDecodeError):
        return _format_skip(
            parsed,
            "XML_DECODE_FAILED",
            "XML 正文无法按声明或文档字符集安全解码",
        )
    if re.search(r"<!\s*ENTITY\b", text, flags=re.IGNORECASE):
        return _format_skip(
            parsed,
            "XML_ENTITY_UNSUPPORTED",
            "包含 ENTITY 声明的 XML 不自动重写",
        )
    if re.search(r"<!\s*DOCTYPE\b", text, flags=re.IGNORECASE):
        return _format_skip(
            parsed,
            "XML_DTD_UNSUPPORTED",
            "包含 DTD 的 XML 不自动重写",
        )
    parse_text = _XML_DECLARATION_RE.sub("", text, count=1)
    if "<?" in parse_text:
        return _format_skip(
            parsed,
            "XML_PROCESSING_INSTRUCTION_UNSUPPORTED",
            "包含额外处理指令的 XML 不自动重写",
        )
    try:
        root = ElementTree.fromstring(parse_text)
    except (ElementTree.ParseError, ValueError):
        return _format_skip(parsed, "XML_PARSE_FAILED", "XML 正文语法无效")
    if not list(_iter_xml_fields(root)):
        return _format_skip(
            parsed,
            "XML_NO_MUTABLE_FIELD",
            "XML 中没有可用于构造语义变体的文本或属性字段",
        )
    return _format_skip(
        parsed,
        "XML_MUTATION_UNAVAILABLE",
        "XML 解析成功，但没有生成与原文不同的安全变体",
    )


def _text_failure_skip(parsed: ParsedRequest) -> MutationSkip:
    decoded = _decode_body(parsed)
    if decoded is None:
        return _format_skip(
            parsed,
            "TEXT_DECODE_FAILED",
            "文本正文无法按声明字符集安全解码",
        )
    text, _encoding = decoded
    if _matching_exploit_marker(text) is None:
        return _format_skip(
            parsed,
            "TEXT_NO_EXPLOIT_MARKER",
            "文本正文没有可确认的共享攻击标记",
        )
    return _format_skip(
        parsed,
        "TEXT_MUTATION_UNAVAILABLE",
        "文本正文可解析，但没有生成与原文不同的安全变体",
    )


def _derive_body_cases_with_diagnostic(
    parsed: ParsedRequest,
    endpoint_path: str,
    query_parts: list[QueryPart],
    fragment: str,
) -> tuple[
    list[tuple[str, ExpectedOutcome, str, ParsedRequest]],
    MutationSkip | None,
]:
    """按声明的 Content-Type 单路分发，避免产生无关解析器噪声。"""
    media_type = _media_type(parsed.headers)
    if media_type == "application/json" or media_type.endswith("+json"):
        cases = _derive_json_body_cases(parsed, endpoint_path, query_parts, fragment)
        return cases, None if cases else _json_failure_skip(parsed)
    if media_type == "application/x-www-form-urlencoded":
        cases = _derive_form_body_cases(parsed, endpoint_path, query_parts, fragment)
        return cases, None if cases else _form_failure_skip(parsed)
    if media_type == "multipart/form-data":
        cases = _derive_multipart_body_cases(
            parsed,
            endpoint_path,
            query_parts,
            fragment,
        )
        return cases, None if cases else _multipart_failure_skip(parsed)
    if media_type in _XML_MEDIA_TYPES or media_type.endswith("+xml"):
        cases = _derive_xml_body_cases(parsed, endpoint_path, query_parts, fragment)
        return cases, None if cases else _xml_failure_skip(parsed)
    if media_type.startswith("text/") or media_type in _TEXTUAL_MEDIA_TYPES:
        cases = _derive_text_body_cases(parsed, endpoint_path, query_parts, fragment)
        return cases, None if cases else _text_failure_skip(parsed)

    if not media_type:
        decoded = _decode_body(parsed)
        if decoded is not None and decoded[0].lstrip().startswith(("{", "[")):
            cases = _derive_json_body_cases(
                parsed,
                endpoint_path,
                query_parts,
                fragment,
            )
        else:
            cases = _derive_text_body_cases(
                parsed,
                endpoint_path,
                query_parts,
                fragment,
            )
        return cases, (
            None
            if cases
            else _format_skip(
                parsed,
                "CONTENT_TYPE_MISSING",
                "未声明 Content-Type，且无法保守推导正文变体",
            )
        )

    return [], _format_skip(
        parsed,
        "CONTENT_TYPE_UNSUPPORTED",
        "该 Content-Type 暂无安全的自动 mutation 策略",
    )


def _benign_response() -> bytes:
    return (
        b"HTTP/1.1 200 OK\r\n"
        b"Content-Type: text/plain\r\n"
        b"Content-Length: 2\r\n"
        b"Connection: close\r\n\r\nOK"
    )


def _validation_target_for_case(name: str) -> ValidationTarget:
    """将派生样本绑定到它真正能够证明的检测目标。"""
    if name == "positive-original" or name.startswith("negative-uploaded-"):
        return "generic"
    if name.startswith(("positive-response-", "negative-response-")):
        return "response_detection"
    if name.startswith("negative-transaction-"):
        return "transaction_specificity"
    return "request_detection"


def derive_http_cases_with_diagnostics(
    request: str | bytes,
    response: str | bytes,
) -> TrafficDerivation:
    """生成正负样本，并记录未执行正文 mutation 的结构化原因。"""
    parsed = parse_http_request(request)
    response_bytes = _response_message_bytes(response) if response else b""
    path, query_parts, fragment = _split_target(parsed.target)
    attack = _find_attack_parameter(query_parts)
    cases: list[DerivedCase] = []
    mutation_skips: list[MutationSkip] = []

    def add(
        name: str,
        expected: ExpectedOutcome,
        reason: str,
        variant: ParsedRequest,
        variant_response: bytes = response_bytes,
        mss: int | None = None,
    ) -> None:
        cases.append((name, expected, reason, variant.render(), variant_response, mss))

    add("positive-original", "alert", "原始攻击证据", parsed)
    add(
        "positive-host-changed",
        "alert",
        "Host 属于动态部署字段，不应影响检测",
        replace(parsed, headers=_set_header(parsed.headers, "Host", "variant.invalid")),
    )
    add(
        "positive-header-order-changed",
        "alert",
        "HTTP 头字段顺序不应影响 URI 检测",
        replace(parsed, headers=tuple(reversed(parsed.headers))),
    )
    add(
        "positive-segmented",
        "alert",
        "同一攻击报文跨多个 TCP 段传输",
        parsed,
        mss=32,
    )
    if len(parsed.body) > 1:
        body_mss = max(1, min(16, len(parsed.body) // 2 or 1))
        add(
            "positive-body-segmented",
            "alert",
            "请求正文中的攻击内容跨多个 TCP 段传输",
            parsed,
            mss=body_mss,
        )

    response_cases, response_skip = _derive_response_cases_with_diagnostic(
        parsed,
        response_bytes,
    )
    if response_skip is not None:
        mutation_skips.append(response_skip)
    for name, expected, reason, variant_response, mss in response_cases:
        add(
            name,
            expected,
            reason,
            parsed,
            variant_response,
            mss=mss,
        )

    if query_parts and attack is not None:
        extra_parts = [
            *query_parts,
            QueryPart(_unique_parameter_name(query_parts, "trace"), "1"),
        ]
        add(
            "positive-extra-parameter",
            "alert",
            "增加无关参数后攻击语义保持不变",
            replace(parsed, target=_render_target(path, extra_parts, fragment)),
        )
        if len(query_parts) > 1:
            add(
                "positive-parameter-order-changed",
                "alert",
                "查询参数顺序变化但攻击值不变",
                replace(
                    parsed,
                    target=_render_target(path, list(reversed(query_parts)), fragment),
                ),
            )

        decoded_attack = unquote(attack.value)
        encoded_attack = quote(decoded_attack, safe="")
        if encoded_attack.lower() != attack.value.lower():
            add(
                "positive-url-encoded",
                "alert",
                "攻击参数使用等价 URL 编码",
                replace(
                    parsed,
                    target=_render_target(
                        path,
                        _replace_query_value(query_parts, attack, encoded_attack),
                        fragment,
                    ),
                ),
            )

        if attack.kind == "file_path" and re.match(r"^[a-zA-Z]:[\\/]", decoded_attack):
            lower_value = decoded_attack.lower()
            if lower_value != decoded_attack:
                add(
                    "positive-case-changed",
                    "alert",
                    "Windows 文件路径大小写变化仍是同一攻击意图",
                    replace(
                        parsed,
                        target=_render_target(
                            path,
                            _replace_query_value(query_parts, attack, lower_value),
                            fragment,
                        ),
                    ),
                )
            slash_value = decoded_attack.replace("\\", "/")
            if slash_value != decoded_attack:
                add(
                    "positive-equivalent-payload",
                    "alert",
                    "Windows 文件路径使用等价斜杠表示",
                    replace(
                        parsed,
                        target=_render_target(
                            path,
                            _replace_query_value(query_parts, attack, slash_value),
                            fragment,
                        ),
                    ),
                )

        benign_values = ["", "report.pdf"]
        if attack.kind == "file_path":
            benign_values.append("documents/report.pdf")
        for index, benign_value in enumerate(benign_values, start=1):
            label = "empty" if benign_value == "" else f"benign-{index}"
            add(
                f"negative-same-endpoint-{label}",
                "no_alert",
                "相同接口和参数名，但参数不包含攻击值",
                replace(
                    parsed,
                    target=_render_target(
                        path,
                        _replace_query_value(query_parts, attack, benign_value),
                        fragment,
                    ),
                ),
                _benign_response(),
            )

        add(
            "negative-different-endpoint-same-value",
            "no_alert",
            "攻击字符串位于其他接口，不属于当前漏洞入口",
            replace(
                parsed,
                target=_render_target("/not-vulnerable", query_parts, fragment),
            ),
            _benign_response(),
        )
        benign_parts = _replace_query_value(query_parts, attack, "report.pdf")
        add(
            "negative-attack-value-in-user-agent",
            "no_alert",
            "攻击字符串只出现在 User-Agent，不在漏洞参数中",
            replace(
                parsed,
                target=_render_target(path, benign_parts, fragment),
                headers=_set_header(parsed.headers, "User-Agent", decoded_attack),
            ),
            _benign_response(),
        )

    if parsed.body:
        protocol_skip = _body_rewrite_skip(parsed)
        if protocol_skip is not None:
            mutation_skips.append(protocol_skip)
        else:
            body_cases, format_skip = _derive_body_cases_with_diagnostic(
                parsed,
                path,
                query_parts,
                fragment,
            )
            if format_skip is not None:
                mutation_skips.append(format_skip)
            for name, expected, reason, variant in body_cases:
                add(
                    name,
                    expected,
                    reason,
                    variant,
                    _benign_response() if expected == "no_alert" else response_bytes,
                )

    if response_bytes:
        unrelated_path = (
            "/unrelated-endpoint" if path == "/not-vulnerable" else "/not-vulnerable"
        )
        add(
            "negative-transaction-different-endpoint-same-response",
            "no_alert",
            "其他接口保留相同请求证据并返回相同内容，不应冒充当前漏洞事务",
            replace(
                parsed,
                target=_render_target(unrelated_path, query_parts, fragment),
            ),
            response_bytes,
        )

    if not any(case[1] == "no_alert" for case in cases):
        unrelated_path = (
            "/unrelated-endpoint" if path == "/not-vulnerable" else "/not-vulnerable"
        )
        add(
            "negative-different-endpoint-fallback",
            "no_alert",
            "请求方法、参数和头部保持不变，但访问非漏洞接口",
            replace(
                parsed,
                target=_render_target(unrelated_path, query_parts, fragment),
            ),
            _benign_response(),
        )

    # 相同字节的普通变体只保留一个；分段样本通过 mss 区分。
    unique: list[DerivedCase] = []
    seen: set[tuple[ExpectedOutcome, bytes, bytes, int | None]] = set()
    for case in cases:
        key = (case[1], case[3], case[4], case[5])
        if key in seen:
            continue
        seen.add(key)
        unique.append(case)
    return TrafficDerivation(tuple(unique), tuple(mutation_skips))


def derive_http_cases(
    request: str | bytes,
    response: str | bytes,
) -> list[DerivedCase]:
    """兼容旧调用方，继续返回可直接遍历和修改的普通 list。"""
    return list(derive_http_cases_with_diagnostics(request, response).cases)


def _materialize_semantic_request(
    parsed: ParsedRequest,
    changes: tuple[SemanticRequestChange, ...],
    expected: ExpectedOutcome,
) -> tuple[ParsedRequest | None, MutationSkip | None]:
    """把受限字段变更应用到已解析请求；不接受原始报文注入。"""
    location = changes[0].location
    if any(change.location != location for change in changes):
        return None, _semantic_skip(
            "SEMANTIC_MIXED_LOCATIONS",
            "一次 semantic testcase 只能修改 query、JSON 或 form 中的一种表示",
        )

    if location == "query":
        path, parts, fragment = _split_target(parsed.target)
        updated = list(parts)
        neutralized_attack = False
        added_field = False
        for change in changes:
            indexes = [
                index
                for index, part in enumerate(updated)
                if unquote_plus(part.name).casefold() == change.field.casefold()
            ]
            if not indexes and expected == "no_alert":
                updated.append(
                    QueryPart(
                        quote_plus(change.field, safe=""),
                        quote_plus(change.value, safe=""),
                        True,
                    )
                )
                added_field = True
                continue
            if len(indexes) != 1:
                return None, _semantic_skip(
                    "SEMANTIC_FIELD_NOT_UNIQUE",
                    f"query 字段 {change.field!r} 必须在原始请求中恰好出现一次",
                )
            index = indexes[0]
            original_value = unquote_plus(updated[index].value)
            neutralized_attack = neutralized_attack or (
                contains_exploit_marker(original_value)
                and not contains_exploit_marker(change.value)
            )
            updated[index] = QueryPart(
                updated[index].name,
                quote_plus(change.value, safe=""),
                True,
            )
        if added_field and not neutralized_attack:
            return None, _semantic_skip(
                "SEMANTIC_ATTACK_FIELD_NOT_NEUTRALIZED",
                "新增无关 query 字段的负样本必须同时把原攻击字段改成非攻击值",
            )
        return replace(parsed, target=_render_target(path, updated, fragment)), None

    protocol_skip = _body_rewrite_skip(parsed)
    if protocol_skip is not None:
        return None, _semantic_skip(
            "SEMANTIC_BODY_REWRITE_BLOCKED",
            protocol_skip.detail,
        )

    if location == "json":
        parsed_json = _parse_json_body(parsed)
        if parsed_json is None:
            return None, _semantic_skip(
                "SEMANTIC_JSON_UNAVAILABLE",
                "原始请求正文不是可安全改写的 JSON",
            )
        document, encoding = parsed_json
        if not isinstance(document, dict):
            return None, _semantic_skip(
                "SEMANTIC_JSON_OBJECT_REQUIRED",
                "semantic JSON testcase 当前只支持对象字段",
            )
        updated_document = copy.deepcopy(document)
        neutralized_attack = False
        added_field = False
        for change in changes:
            path = tuple(change.field.split("."))
            current: object = updated_document
            for part in path[:-1]:
                if not isinstance(current, dict) or part not in current:
                    return None, _semantic_skip(
                        "SEMANTIC_FIELD_NOT_FOUND",
                        f"JSON 字段 {change.field!r} 不存在",
                    )
                current = current[part]
            leaf = path[-1]
            if (
                isinstance(current, dict)
                and leaf not in current
                and expected == "no_alert"
                and len(path) == 1
            ):
                current[leaf] = change.value
                added_field = True
                continue
            if not isinstance(current, dict) or leaf not in current:
                return None, _semantic_skip(
                    "SEMANTIC_FIELD_NOT_FOUND",
                    f"JSON 字段 {change.field!r} 不存在",
                )
            if not isinstance(current[leaf], str):
                return None, _semantic_skip(
                    "SEMANTIC_STRING_FIELD_REQUIRED",
                    f"JSON 字段 {change.field!r} 的原始值必须是字符串",
                )
            neutralized_attack = neutralized_attack or (
                contains_exploit_marker(current[leaf])
                and not contains_exploit_marker(change.value)
            )
            current[leaf] = change.value
        if added_field and not neutralized_attack:
            return None, _semantic_skip(
                "SEMANTIC_ATTACK_FIELD_NOT_NEUTRALIZED",
                "新增无关 JSON 字段的负样本必须同时把原攻击字段改成非攻击值",
            )
        body = _json_bytes(updated_document, encoding)
        if body is None:
            return None, _semantic_skip(
                "SEMANTIC_BODY_ENCODING_FAILED", "无法使用原始字符集编码 JSON"
            )
        return _replace_body(parsed, body), None

    parsed_form = _parse_form_body(parsed)
    if parsed_form is None:
        return None, _semantic_skip(
            "SEMANTIC_FORM_UNAVAILABLE",
            "原始请求正文不是可安全改写的 application/x-www-form-urlencoded",
        )
    parts, encoding = parsed_form
    updated_parts = list(parts)
    neutralized_attack = False
    added_field = False
    for change in changes:
        indexes = [
            index
            for index, part in enumerate(updated_parts)
            if unquote_plus(part.name).casefold() == change.field.casefold()
        ]
        if not indexes and expected == "no_alert":
            updated_parts.append(
                QueryPart(
                    quote_plus(change.field, safe=""),
                    quote_plus(change.value, safe=""),
                    True,
                )
            )
            added_field = True
            continue
        if len(indexes) != 1:
            return None, _semantic_skip(
                "SEMANTIC_FIELD_NOT_UNIQUE",
                f"form 字段 {change.field!r} 必须在原始请求中恰好出现一次",
            )
        index = indexes[0]
        original_value = unquote_plus(updated_parts[index].value)
        neutralized_attack = neutralized_attack or (
            contains_exploit_marker(original_value)
            and not contains_exploit_marker(change.value)
        )
        updated_parts[index] = QueryPart(
            updated_parts[index].name,
            quote_plus(change.value, safe=""),
            True,
        )
    if added_field and not neutralized_attack:
        return None, _semantic_skip(
            "SEMANTIC_ATTACK_FIELD_NOT_NEUTRALIZED",
            "新增无关 form 字段的负样本必须同时把原攻击字段改成非攻击值",
        )
    body = _encode_body("&".join(part.render() for part in updated_parts), encoding)
    if body is None:
        return None, _semantic_skip(
            "SEMANTIC_BODY_ENCODING_FAILED", "无法使用原始字符集编码 form 正文"
        )
    return _replace_body(parsed, body), None


def materialize_semantic_testcases(
    output_dir: str | Path,
    request: str | bytes,
    response: str | bytes,
    testcases: tuple[SemanticTestcase, ...],
    *,
    config: PcapConfig | None = None,
    sample_offset: int = 0,
) -> TrafficSampleList:
    """把 LLM 语义 testcase 确定性转换为真实 HTTP/PCAP。"""
    if not testcases:
        return TrafficSampleList([])
    output_path = Path(output_dir).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    parsed = parse_http_request(request)
    response_bytes = _response_message_bytes(response) if response else b""
    base = config or PcapConfig()
    samples: list[TrafficSample] = []
    skips: list[MutationSkip] = []
    seen_requests: set[bytes] = {parsed.render()}

    for testcase_index, testcase in enumerate(testcases, start=1):
        variant, skip = _materialize_semantic_request(
            parsed,
            testcase.changes,
            testcase.expected,
        )
        if skip is not None:
            skips.append(skip)
            continue
        assert variant is not None
        request_bytes = variant.render()
        if request_bytes in seen_requests:
            skips.append(
                _semantic_skip(
                    "SEMANTIC_DUPLICATE_REQUEST",
                    f"semantic testcase {testcase_index} 没有产生新的请求字节",
                )
            )
            continue
        seen_requests.add(request_bytes)
        name = f"semantic-{'positive' if testcase.expected == 'alert' else 'negative'}-{testcase_index:02d}"
        flow_index = sample_offset + len(samples)
        client_port = base.client_port + flow_index
        if client_port > 65535:
            client_port = 40000 + flow_index
        sample_config = replace(
            base,
            client_port=client_port,
            client_initial_seq=(base.client_initial_seq + flow_index * 100_000) % (2**32),
            server_initial_seq=(base.server_initial_seq + flow_index * 100_000) % (2**32),
            timestamp=base.timestamp + flow_index,
        )
        sample_response = response_bytes if testcase.expected == "alert" else _benign_response()
        pcap_path = generate_pcap(
            str(output_path / f"{name}.pcap"),
            request_bytes,
            sample_response,
            config=sample_config,
        )
        samples.append(
            TrafficSample(
                name=name,
                expected=testcase.expected,
                reason=testcase.reason,
                source="semantic",
                pcap_path=pcap_path,
                request=request_bytes,
                response=sample_response,
                validates="request_detection",
            )
        )
    return TrafficSampleList(samples, tuple(skips))


def build_traffic_matrix(
    output_dir: str | Path,
    request: str | bytes,
    response: str | bytes,
    *,
    config: PcapConfig | None = None,
    uploaded_negative_pcaps: tuple[str | Path, ...] = (),
) -> TrafficSampleList:
    """生成独立 PCAP，并在 list 兼容返回值上携带 mutation 诊断。"""
    output_path = Path(output_dir).resolve()
    output_path.mkdir(parents=True, exist_ok=True)
    base = config or PcapConfig()
    samples: list[TrafficSample] = []
    derivation = derive_http_cases_with_diagnostics(request, response)

    for index, (name, expected, reason, req, resp, mss) in enumerate(
        derivation.cases
    ):
        client_port = base.client_port + index
        if client_port > 65535:
            client_port = 40000 + index
        sample_config = replace(
            base,
            client_port=client_port,
            client_initial_seq=(base.client_initial_seq + index * 100_000) % (2**32),
            server_initial_seq=(base.server_initial_seq + index * 100_000) % (2**32),
            timestamp=base.timestamp + index,
            mss=mss or base.mss,
        )
        pcap_path = generate_pcap(
            str(output_path / f"{name}.pcap"),
            req,
            resp,
            config=sample_config,
        )
        samples.append(
            TrafficSample(
                name=name,
                expected=expected,
                reason=reason,
                source="original" if name == "positive-original" else "derived",
                pcap_path=pcap_path,
                request=req,
                response=resp,
                validates=_validation_target_for_case(name),
            )
        )

    used_names = {sample.name for sample in samples}
    for index, value in enumerate(uploaded_negative_pcaps, start=1):
        source_pcap = Path(value).resolve()
        if not source_pcap.is_file():
            raise ValueError(f"用户负样本 PCAP 不存在：{source_pcap.name}")
        name = f"negative-uploaded-{index}"
        while name in used_names:
            index += 1
            name = f"negative-uploaded-{index}"
        used_names.add(name)
        suffix = source_pcap.suffix if source_pcap.suffix else ".pcap"
        pcap_path = output_path / f"{name}{suffix}"
        if source_pcap != pcap_path.resolve():
            shutil.copyfile(source_pcap, pcap_path)
        samples.append(
            TrafficSample(
                name=name,
                expected="no_alert",
                reason="用户提供的负样本",
                source="uploaded",
                pcap_path=pcap_path,
                validates="generic",
            )
        )
    return TrafficSampleList(samples, derivation.mutation_skips)
