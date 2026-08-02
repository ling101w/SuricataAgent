"""规则生成、编译、诊断和样本派生共享的领域知识。"""

from __future__ import annotations

import re
from types import MappingProxyType
from typing import Literal, Sequence


Direction = Literal["request", "response"]
CandidateRole = Literal["precision", "robust", "alternative_evidence"]
DetectionScope = Literal["case_specific", "exploit_family", "success_indicator"]

# 模型输出、schema 解析和批量编译共同遵守固定的候选角色契约。
CANDIDATE_ROLES: tuple[CandidateRole, ...] = (
    "precision",
    "robust",
    "alternative_evidence",
)
CANDIDATE_ROLE_GUIDANCE = MappingProxyType(
    {
        "precision": "保留 endpoint 与利用语义，以尽量降低误报",
        "robust": "保留最小 endpoint 身份锚点，减少参数名和具体 payload 绑定",
        "alternative_evidence": "使用独立证据；响应候选仅作为补充成功指标",
    }
)


def candidate_detection_scope(
    role: CandidateRole,
    direction: Direction,
) -> DetectionScope:
    """根据固定角色契约确定检测层级，禁止由模型自由抬高候选优先级。"""
    if role == "alternative_evidence" and direction == "response":
        return "success_indicator"
    return "case_specific"
REQUIRED_CANDIDATE_COUNT = len(CANDIDATE_ROLES)
# 保留原常量名供现有调用方使用，但上下界现在都严格等于三个候选。
MIN_CANDIDATES = REQUIRED_CANDIDATE_COUNT
MAX_CANDIDATES = REQUIRED_CANDIDATE_COUNT

POSITIVE_COVERAGE_WEIGHT = 100.0
FALSE_POSITIVE_PENALTY = 50
PCRE_PENALTY = 5

# 只列出能够由确定性编译器确认方向的 HTTP sticky buffer。
REQUEST_BUFFERS = frozenset(
    {
        "http.accept",
        "http.accept_enc",
        "http.accept_lang",
        "http.cookie",
        "http.host",
        "http.host.raw",
        "http.method",
        "http.referer",
        "http.request_body",
        "http.request_header",
        "http.request_header.raw",
        "http.request_line",
        "http.uri",
        "http.uri.raw",
        "http.user_agent",
    }
)
RESPONSE_BUFFERS = frozenset(
    {
        "file_data",
        "http.location",
        "http.response_body",
        "http.response_header",
        "http.response_header.raw",
        "http.response_line",
        "http.stat_code",
        "http.stat_msg",
    }
)
SHARED_BUFFERS = frozenset(
    {
        "http.connection",
        "http.content_len",
        "http.content_type",
        "http.header",
        "http.header.raw",
        "http.protocol",
        "http.start",
    }
)
KNOWN_BUFFERS = REQUEST_BUFFERS | RESPONSE_BUFFERS | SHARED_BUFFERS
SUPPORTED_BUFFERS = KNOWN_BUFFERS

# 这些字段随部署或每次请求变化，不能成为检测条件。
DYNAMIC_HTTP_FIELDS = ("Host", "Content-Length", "Cookie", "Set-Cookie")
DYNAMIC_BUFFER_FIELDS = MappingProxyType(
    {
        "http.content_len": "Content-Length",
        "http.cookie": "Cookie",
        "http.host": "Host",
        "http.host.raw": "Host",
    }
)
HEADER_BUFFERS = frozenset(
    {
        "http.header",
        "http.header.raw",
        "http.request_header",
        "http.request_header.raw",
        "http.response_header",
        "http.response_header.raw",
    }
)
FORBIDDEN_MODEL_FEATURE_BUFFERS = frozenset(
    {"http.method", *DYNAMIC_BUFFER_FIELDS.keys()}
)
MODEL_FEATURE_BUFFERS = SUPPORTED_BUFFERS - FORBIDDEN_MODEL_FEATURE_BUFFERS

# 用于区分普通接口结构和攻击语义；所有消费者都必须复用同一集合。
EXPLOIT_MARKERS = (
    "../",
    "..\\",
    "%2e",
    "%252e",
    "%5c",
    "%255c",
    "/etc/",
    "/proc/",
    "\\windows\\",
    "win.ini",
    "boot.ini",
    "${",
    "<script",
    "javascript:",
    "union select",
    "sleep(",
    "waitfor delay",
    "whoami",
    "/bin/sh",
    "sh -c",
    "bash -c",
    "powershell",
    "cmd.exe",
    "<!doctype",
    "<!entity",
    "://",
    ";",
    "|",
)

_PARAMETER_NAME_RE = re.compile(
    r"^(?:[?&])?[A-Za-z_][A-Za-z0-9_.\-\[\]]{0,63}=$"
)
_WINDOWS_PATH_RE = re.compile(r"(?i)\b[a-z]:[\\/]")
_REQUEST_LINE_TARGET_RE = re.compile(
    r"^[A-Z][A-Z0-9!#$%&'*+.^_`|~-]*\s+(\S+)",
    re.IGNORECASE,
)


def candidate_count_is_valid(count: int) -> bool:
    """判断候选数量是否满足模型输出和批量编译契约。"""
    return count == REQUIRED_CANDIDATE_COUNT


def candidate_roles_are_valid(roles: Sequence[str]) -> bool:
    """判断候选是否严格按固定角色顺序出现，且每个角色只出现一次。"""
    return tuple(roles) == CANDIDATE_ROLES


def buffers_for_direction(direction: Direction) -> frozenset[str]:
    """返回指定流量方向可使用的 sticky buffer。"""
    directional = REQUEST_BUFFERS if direction == "request" else RESPONSE_BUFFERS
    return directional | SHARED_BUFFERS


def is_buffer_allowed(direction: Direction, buffer: str) -> bool:
    """判断 sticky buffer 是否能用于指定方向。"""
    return buffer in buffers_for_direction(direction)


def contains_exploit_marker(value: str) -> bool:
    """判断文本是否包含共享攻击语义标记。"""
    lowered = value.casefold()
    return any(marker in lowered for marker in EXPLOIT_MARKERS)


def is_parameter_name_only(value: str) -> bool:
    """判断 content 是否只有 URI 参数名而没有参数值。"""
    return _PARAMETER_NAME_RE.fullmatch(value.strip()) is not None


def looks_like_windows_path(value: str) -> bool:
    """判断文本是否包含盘符开头的 Windows 文件路径。"""
    return _WINDOWS_PATH_RE.search(value) is not None


def is_structural_match(buffer: str, value: str, *, kind: str = "content") -> bool:
    """判断匹配项是否只描述协议或接口结构，而没有攻击语义。"""
    stripped = value.strip()
    if contains_exploit_marker(stripped) or looks_like_windows_path(stripped):
        return False
    if kind == "pcre":
        return True
    if buffer == "http.method" or is_parameter_name_only(stripped):
        return True
    return buffer in {"http.uri", "http.uri.raw"}


def is_endpoint_match(buffer: str, value: str) -> bool:
    """判断 content 是否是可复用的 HTTP endpoint 路径锚点。"""
    candidate = value.strip()
    if buffer == "http.request_line":
        match = _REQUEST_LINE_TARGET_RE.match(candidate)
        if match is None:
            return False
        candidate = match.group(1)
    elif buffer not in {"http.uri", "http.uri.raw"}:
        return False
    candidate = candidate.split("?", 1)[0]
    return (
        candidate.startswith("/")
        and candidate not in {"/", "//"}
        and not contains_exploit_marker(candidate)
        and not looks_like_windows_path(candidate)
    )


__all__ = [
    "CANDIDATE_ROLES",
    "CANDIDATE_ROLE_GUIDANCE",
    "CandidateRole",
    "DYNAMIC_BUFFER_FIELDS",
    "DYNAMIC_HTTP_FIELDS",
    "DetectionScope",
    "Direction",
    "EXPLOIT_MARKERS",
    "FALSE_POSITIVE_PENALTY",
    "FORBIDDEN_MODEL_FEATURE_BUFFERS",
    "HEADER_BUFFERS",
    "KNOWN_BUFFERS",
    "MAX_CANDIDATES",
    "MIN_CANDIDATES",
    "MODEL_FEATURE_BUFFERS",
    "PCRE_PENALTY",
    "POSITIVE_COVERAGE_WEIGHT",
    "REQUEST_BUFFERS",
    "REQUIRED_CANDIDATE_COUNT",
    "RESPONSE_BUFFERS",
    "SHARED_BUFFERS",
    "SUPPORTED_BUFFERS",
    "buffers_for_direction",
    "candidate_count_is_valid",
    "candidate_detection_scope",
    "candidate_roles_are_valid",
    "contains_exploit_marker",
    "is_buffer_allowed",
    "is_endpoint_match",
    "is_parameter_name_only",
    "is_structural_match",
    "looks_like_windows_path",
]
