"""Suricata 规则策略、语法和 PCAP 回放验证。"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import threading
import uuid
from collections.abc import Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, TypedDict


DEFAULT_SID_START = 123
MAX_COMMAND_OUTPUT_CHARS = 12_000
PROJECT_DIR = Path(__file__).resolve().parent
LOCAL_SURICATA_DIR = PROJECT_DIR / "suricata"
RUNTIME_DIR = PROJECT_DIR / ".runtime"
_SURICATA_PROCESS_LOCK = threading.Lock()


class RuleValidationResult(TypedDict):
    passed: bool
    validation_level: str
    completed_stages: list[str]
    failed_stage: str | None
    error_code: str | None
    retryable: bool
    syntax_ok: bool | None
    positive_match_ok: bool | None
    negative_match_ok: bool | None
    expected_sids: list[int]
    positive_matched_sids: list[int]
    negative_matched_sids: list[int]
    errors: list[str]
    warnings: list[str]
    command_output: str
    sample_results: list[dict[str, object]]
    positive_coverage: float
    false_positive_count: int
    quality_warnings: list[str]


class StaticRuleCheck(TypedDict):
    passed: bool
    rules: str
    rule_count: int
    expected_sids: list[int]
    errors: list[str]


class SuricataRuntimeCheck(TypedDict):
    ok: bool
    suricata_bin: str | None
    config_path: str
    error_code: str | None
    message: str | None


@dataclass(frozen=True)
class RulePolicy:
    """独立于 Suricata 语法的项目级规则约束。"""

    sid_start: int | None = DEFAULT_SID_START
    require_contiguous_sids: bool = True
    allowed_actions: frozenset[str] = field(
        default_factory=lambda: frozenset({"alert"})
    )
    allowed_protocols: frozenset[str] | None = None
    allowed_directions: frozenset[str] | None = None
    required_flow_options: frozenset[str] = field(default_factory=frozenset)
    forbidden_keywords: frozenset[str] = field(
        default_factory=lambda: frozenset(
            {
                "dataset",
                "datarep",
                "lua",
                "filestore",
                "tag",
                "xbits",
                "flowbits",
            }
        )
    )
    require_rev: bool = False
    max_content_count: int = 64
    max_pcre_count: int = 8
    max_pcre_bytes: int = 4_096
    max_byte_jump_count: int = 4
    positive_match_mode: Literal["all", "any"] = "all"
    max_rules: int = 20
    max_rule_bytes: int = 128 * 1024


DEFAULT_RULE_POLICY = RulePolicy()
RULE_ACTION_RE = re.compile(
    r"^\s*(alert|pass|drop|reject|rejectsrc|rejectdst|rejectboth)\b",
    flags=re.IGNORECASE,
)
SID_OPTION_RE = re.compile(r"^\s*sid\s*:\s*(\d+)\s*$", re.IGNORECASE)
REV_OPTION_RE = re.compile(r"^\s*rev\s*:\s*(\d+)\s*$", re.IGNORECASE)
OPTION_NAME_RE = re.compile(r"^\s*([A-Za-z][A-Za-z0-9_.-]*)\s*(?::|$)")


def clean_rule_text(text: str) -> str:
    """移除模型响应外层可选的 Markdown 代码围栏。"""
    text = text.strip()
    text = re.sub(
        r"^```(?:suricata|rules?|text)?\s*",
        "",
        text,
        count=1,
        flags=re.IGNORECASE,
    )
    text = re.sub(r"\s*```$", "", text, count=1)
    return text.strip()


def _split_rule_blocks(rules: str) -> list[str]:
    """提取有效的单行规则或括号配平的多行规则。"""
    blocks: list[str] = []
    current: list[str] = []
    depth = 0
    saw_options = False
    in_quote = False
    escaped = False

    for raw_line in rules.splitlines():
        line = raw_line.strip()
        if not current and (not line or line.startswith("#")):
            continue

        current.append(line)
        for char in line:
            if escaped:
                escaped = False
                continue
            if char == "\\" and in_quote:
                escaped = True
                continue
            if char == '"':
                in_quote = not in_quote
                continue
            if in_quote:
                continue
            if char == "(":
                saw_options = True
                depth += 1
            elif char == ")" and depth > 0:
                depth -= 1

        if (saw_options and depth == 0) or (not saw_options and not in_quote):
            blocks.append(" ".join(current))
            current = []
            depth = 0
            saw_options = False
            in_quote = False
            escaped = False

    if current:
        blocks.append(" ".join(current))

    return blocks


def _split_options(option_text: str) -> list[str]:
    options: list[str] = []
    current: list[str] = []
    in_quote = False
    escaped = False

    for char in option_text:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and in_quote:
            current.append(char)
            escaped = True
            continue
        if char == '"':
            current.append(char)
            in_quote = not in_quote
            continue
        if char == ";" and not in_quote:
            options.append("".join(current).strip())
            current = []
            continue
        current.append(char)

    if current:
        options.append("".join(current).strip())
    return options


def _rule_sids(rule: str) -> list[int]:
    start = rule.find("(")
    end = rule.rfind(")")
    if start < 0 or end <= start:
        return []

    sids: list[int] = []
    for option in _split_options(rule[start + 1 : end]):
        match = SID_OPTION_RE.fullmatch(option)
        if match:
            sids.append(int(match.group(1)))
    return sids


def _rule_header_tokens(rule: str) -> list[str]:
    return rule.split("(", 1)[0].strip().split()


def _rule_options(rule: str) -> list[str]:
    start = rule.find("(")
    end = rule.rfind(")")
    if start < 0 or end <= start:
        return []
    return _split_options(rule[start + 1 : end])


def _option_name(option: str) -> str | None:
    match = OPTION_NAME_RE.match(option)
    return match.group(1).casefold() if match else None


def _high_risk_pcre(option: str) -> bool:
    """Detect common nested-quantifier shapes that can cause excessive backtracking."""
    value = option.split(":", 1)[1] if ":" in option else ""
    return bool(
        re.search(
            r"\([^)]*(?:\.\*|\.\+|[^\\][+*])[^)]*\)(?:[+*]|\{\d*,?\d*\})",
            value,
        )
    )


def extract_rule_sids(rules: str) -> list[int]:
    """提取真实 SID 选项，忽略注释和引号内的相似文本。"""
    return [sid for rule in _split_rule_blocks(rules) for sid in _rule_sids(rule)]


def static_check_rules(
    rules: str,
    *,
    policy: RulePolicy = DEFAULT_RULE_POLICY,
) -> StaticRuleCheck:
    rules = clean_rule_text(rules)
    errors: list[str] = []

    if not rules:
        return {
            "passed": False,
            "rules": rules,
            "rule_count": 0,
            "expected_sids": [],
            "errors": ["生成的规则为空"],
        }

    if len(rules.encode("utf-8")) > policy.max_rule_bytes:
        errors.append(f"规则内容超过 {policy.max_rule_bytes} 字节限制")

    rule_blocks = _split_rule_blocks(rules)
    if not rule_blocks:
        errors.append("没有发现 Suricata 规则")
    if len(rule_blocks) > policy.max_rules:
        errors.append(f"规则数量超过 {policy.max_rules} 条限制")

    expected_sids: list[int] = []
    for index, rule in enumerate(rule_blocks, start=1):
        action_match = RULE_ACTION_RE.match(rule)
        if not action_match:
            errors.append(f"第 {index} 条规则缺少有效 action")
        elif action_match.group(1).lower() not in policy.allowed_actions:
            errors.append(
                f"第 {index} 条规则 action 必须是 "
                f"{sorted(policy.allowed_actions)}"
            )

        header_tokens = _rule_header_tokens(rule)
        protocol = header_tokens[1].casefold() if len(header_tokens) >= 2 else None
        if (
            protocol is not None
            and policy.allowed_protocols is not None
            and protocol not in policy.allowed_protocols
        ):
            errors.append(
                f"第 {index} 条规则 protocol 必须是 "
                f"{sorted(policy.allowed_protocols)}"
            )
        direction = next(
            (token for token in header_tokens if token in {"->", "<-", "<>"}),
            None,
        )
        if direction is None:
            errors.append(f"第 {index} 条规则缺少有效方向")
        elif (
            policy.allowed_directions is not None
            and direction not in policy.allowed_directions
        ):
            errors.append(
                f"第 {index} 条规则方向必须是 "
                f"{sorted(policy.allowed_directions)}"
            )

        options = _rule_options(rule)
        option_names = [name for option in options if (name := _option_name(option))]
        forbidden = sorted(set(option_names) & policy.forbidden_keywords)
        if forbidden:
            errors.append(
                f"第 {index} 条规则包含禁止关键字：{', '.join(forbidden)}"
            )

        flow_options: set[str] = set()
        for option in options:
            if _option_name(option) == "flow" and ":" in option:
                flow_options.update(
                    value.strip().casefold()
                    for value in option.split(":", 1)[1].split(",")
                    if value.strip()
                )
        missing_flow = policy.required_flow_options - flow_options
        if missing_flow:
            errors.append(
                f"第 {index} 条规则缺少 flow 约束：{', '.join(sorted(missing_flow))}"
            )

        rev_count = sum(bool(REV_OPTION_RE.fullmatch(option)) for option in options)
        if policy.require_rev and rev_count != 1:
            errors.append(f"第 {index} 条规则必须包含且仅包含一个 rev")

        content_count = option_names.count("content")
        if content_count > policy.max_content_count:
            errors.append(
                f"第 {index} 条规则 content 数量超过 {policy.max_content_count}"
            )
        pcre_options = [
            option for option in options if _option_name(option) == "pcre"
        ]
        if len(pcre_options) > policy.max_pcre_count:
            errors.append(
                f"第 {index} 条规则 PCRE 数量超过 {policy.max_pcre_count}"
            )
        if any(len(option.encode("utf-8")) > policy.max_pcre_bytes for option in pcre_options):
            errors.append(
                f"第 {index} 条规则单个 PCRE 超过 {policy.max_pcre_bytes} 字节"
            )
        if any(_high_risk_pcre(option) for option in pcre_options):
            errors.append(f"第 {index} 条规则 PCRE 包含高风险嵌套量词")
        byte_jump_count = option_names.count("byte_jump")
        if byte_jump_count > policy.max_byte_jump_count:
            errors.append(
                f"第 {index} 条规则 byte_jump 数量超过 {policy.max_byte_jump_count}"
            )

        sids = _rule_sids(rule)
        if len(sids) != 1:
            errors.append(f"第 {index} 条规则必须包含且仅包含一个 SID")
        else:
            expected_sids.append(sids[0])

    if len(expected_sids) != len(set(expected_sids)):
        duplicates = sorted(
            sid for sid in set(expected_sids) if expected_sids.count(sid) > 1
        )
        errors.append(f"规则存在重复 SID：{duplicates}")

    if (
        policy.sid_start is not None
        and policy.require_contiguous_sids
        and len(expected_sids) == len(rule_blocks)
    ):
        expected_sequence = list(
            range(policy.sid_start, policy.sid_start + len(rule_blocks))
        )
        if expected_sids != expected_sequence:
            errors.append(
                f"SID 必须从 {policy.sid_start} 开始连续递增；"
                f"期望 {expected_sequence}，实际 {expected_sids}"
            )

    return {
        "passed": not errors,
        "rules": rules,
        "rule_count": len(rule_blocks),
        "expected_sids": expected_sids,
        "errors": errors,
    }


def read_alert_sids(log_dir: Path) -> list[int]:
    """从 EVE JSON 和 fast.log 中读取并去重告警 SID。"""
    matched_sids: set[int] = set()
    eve_path = log_dir / "eve.json"
    if eve_path.is_file():
        with eve_path.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get("event_type") != "alert":
                    continue
                sid = event.get("alert", {}).get("signature_id")
                if isinstance(sid, int):
                    matched_sids.add(sid)
                elif isinstance(sid, str) and sid.isdigit():
                    matched_sids.add(int(sid))

    fast_log_path = log_dir / "fast.log"
    if fast_log_path.is_file():
        text = fast_log_path.read_text(encoding="utf-8", errors="replace")
        matched_sids.update(
            int(sid) for sid in re.findall(r"\[\d+:(\d+):\d+\]", text)
        )
    return sorted(matched_sids)


def run_command(
    command: list[str],
    timeout: int = 60,
) -> subprocess.CompletedProcess[str]:
    environment = os.environ.copy()
    # Suricata 不需要模型凭据，避免把密钥传给外部子进程。
    environment.pop("LLM_API_KEY", None)
    environment.pop("DEEPSEEK_API_KEY", None)
    executable_dir = str(Path(command[0]).resolve().parent)
    path_entries = [executable_dir]

    if os.name == "nt":
        system_root = Path(os.getenv("SystemRoot", r"C:\Windows"))
        for directory in (
            system_root / "System32" / "Npcap",
            system_root / "System32",
        ):
            if (directory / "wpcap.dll").is_file():
                path_entries.append(str(directory))
                break

    current_path = environment.get("PATH", "")
    environment["PATH"] = os.pathsep.join(
        [*path_entries, current_path] if current_path else path_entries
    )

    working_dir: str | None = None
    if "-c" in command:
        config_index = command.index("-c") + 1
        if config_index < len(command):
            working_dir = str(Path(command[config_index]).resolve().parent)

    def execute_native() -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            check=False,
            cwd=working_dir,
            env=environment,
        )

    # Windows 便携版会在配置目录使用相对路径，串行运行可避免日志争用。
    if os.name == "nt":
        with _SURICATA_PROCESS_LOCK:
            return execute_native()
    return execute_native()


def _command_output(process: subprocess.CompletedProcess[str]) -> str:
    output = "\n".join(
        part.strip() for part in (process.stdout, process.stderr) if part.strip()
    )
    return output[-MAX_COMMAND_OUTPUT_CHARS:]


@contextmanager
def _shared_temporary_directory(prefix: str):
    """创建继承工作区 ACL 的临时验证目录。"""
    RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
    path = RUNTIME_DIR / f"{prefix}{uuid.uuid4().hex}"
    path.mkdir()
    try:
        yield str(path)
    finally:
        shutil.rmtree(path, ignore_errors=True)


def _run_suricata_command(
    command: list[str],
    *,
    timeout: int,
    log_dir: Path,
) -> tuple[subprocess.CompletedProcess[str], Path]:
    """运行 Suricata；Windows 初始化超时时使用新日志目录重试一次。"""
    try:
        return run_command(command, timeout=timeout), log_dir
    except subprocess.TimeoutExpired:
        if os.name != "nt":
            raise

    retry_log_dir = log_dir.parent / f"{log_dir.name}-retry-{uuid.uuid4().hex}"
    retry_log_dir.mkdir()
    retry_command = command.copy()
    log_index = retry_command.index("-l") + 1
    retry_command[log_index] = str(retry_log_dir)
    return run_command(retry_command, timeout=timeout), retry_log_dir


def run_suricata_on_pcap(
    *,
    suricata_bin: str,
    config_path: str,
    rules_path: Path,
    pcap_path: Path,
    log_dir: Path,
    timeout: int,
) -> tuple[bool, list[int], str]:
    log_dir.mkdir(parents=True, exist_ok=True)
    process, actual_log_dir = _run_suricata_command(
        [
            suricata_bin,
            "-c",
            config_path,
            "-S",
            str(rules_path),
            "-r",
            str(pcap_path),
            "-l",
            str(log_dir),
            "-k",
            "none",
        ],
        timeout=timeout,
        log_dir=log_dir,
    )
    return (
        process.returncode == 0,
        read_alert_sids(actual_log_dir),
        _command_output(process),
    )


def _initial_result(expected_sids: list[int]) -> RuleValidationResult:
    return {
        "passed": False,
        "validation_level": "none",
        "completed_stages": [],
        "failed_stage": None,
        "error_code": None,
        "retryable": False,
        "syntax_ok": None,
        "positive_match_ok": None,
        "negative_match_ok": None,
        "expected_sids": expected_sids,
        "positive_matched_sids": [],
        "negative_matched_sids": [],
        "errors": [],
        "warnings": [],
        "command_output": "",
        "sample_results": [],
        "positive_coverage": 0.0,
        "false_positive_count": 0,
        "quality_warnings": [],
    }


def _sample_field(sample: object, name: str, default: object = None) -> object:
    if isinstance(sample, Mapping):
        return sample.get(name, default)
    return getattr(sample, name, default)


def _sample_request_line(sample: object) -> str | None:
    request = _sample_field(sample, "request")
    if not isinstance(request, (str, bytes)):
        return None
    raw = request.encode("utf-8") if isinstance(request, str) else request
    first = re.split(br"\r\n|\n|\r", raw, maxsplit=1)[0]
    return first.decode("latin-1", errors="replace")[:500]


def _rule_scope_contract(rules: str) -> dict[int, tuple[str, str]]:
    """返回 SID 对应的方向和 detection_scope，供样本适用域筛选。"""
    try:
        from suricata_agent.domain.rules.ir import parse_suricata_rules

        return {
            rule.sid: (rule.direction, rule.detection_scope)
            for rule in parse_suricata_rules(rules)
        }
    except Exception:
        # 静态检查仍负责语法；旧调用若无法产生 IR，则按通用样本契约执行。
        return {}


def _sample_expected_sids(
    validates: str,
    expected_rule_sids: set[int],
    rule_contract: Mapping[int, tuple[str, str]],
) -> set[int]:
    if validates == "request_detection":
        return {
            sid
            for sid in expected_rule_sids
            if rule_contract.get(sid, ("request", "case_specific"))[0] == "request"
        }
    if validates == "response_detection":
        return {
            sid
            for sid in expected_rule_sids
            if rule_contract.get(sid, ("response", "success_indicator"))[0] == "response"
        }
    if validates == "transaction_specificity":
        return {
            sid
            for sid in expected_rule_sids
            if rule_contract.get(sid, ("request", "case_specific"))[1]
            == "case_specific"
        }
    return set(expected_rule_sids)


def validate_rule_matrix(
    rules: str,
    samples: Sequence[object],
    *,
    policy: RulePolicy = DEFAULT_RULE_POLICY,
    suricata_bin: str | None = None,
    config_path: str | None = None,
    syntax_timeout: int = 30,
    replay_timeout: int = 60,
) -> RuleValidationResult:
    """逐样本验证规则，每个正样本只要求命中其期望 SID 集合中的任意一个。"""
    static = static_check_rules(rules, policy=policy)
    result = _initial_result(static["expected_sids"])
    if not static["passed"]:
        result["errors"].extend(static["errors"])
        result["failed_stage"] = "static"
        result["error_code"] = "STATIC_RULE_ERROR"
        result["retryable"] = True
        return result

    result["completed_stages"].append("static")
    result["validation_level"] = "static"
    if not samples:
        return _fail(
            result,
            stage="positive",
            code="POSITIVE_PCAP_REQUIRED",
            message="样本矩阵不能为空",
            retryable=False,
        )

    runtime = check_suricata_runtime(
        suricata_bin=suricata_bin,
        config_path=config_path,
    )
    if not runtime["ok"]:
        return _fail(
            result,
            stage="syntax",
            code=runtime["error_code"] or "SURICATA_RUNTIME_ERROR",
            message=runtime["message"] or "Suricata 运行环境不可用",
            retryable=False,
        )
    executable = runtime["suricata_bin"]
    assert executable is not None

    outputs: list[str] = []
    with _shared_temporary_directory("suricata-matrix-") as temp_dir:
        temp_path = Path(temp_dir)
        rules_path = temp_path / "generated.rules"
        syntax_log_dir = temp_path / "syntax-logs"
        syntax_log_dir.mkdir(parents=True, exist_ok=True)
        rules_path.write_text(static["rules"] + "\n", encoding="utf-8")

        try:
            syntax_process, _ = _run_suricata_command(
                [
                    executable,
                    "-T",
                    "-c",
                    runtime["config_path"],
                    "-S",
                    str(rules_path),
                    "-l",
                    str(syntax_log_dir),
                ],
                timeout=syntax_timeout,
                log_dir=syntax_log_dir,
            )
        except subprocess.TimeoutExpired:
            return _fail(
                result,
                stage="syntax",
                code="SURICATA_TIMEOUT",
                message="Suricata 语法验证超时",
                retryable=False,
            )
        except OSError as exc:
            return _fail(
                result,
                stage="syntax",
                code="SURICATA_EXECUTION_ERROR",
                message=f"无法执行 Suricata：{exc}",
                retryable=False,
            )

        outputs.append("===== syntax =====\n" + _command_output(syntax_process))
        result["syntax_ok"] = syntax_process.returncode == 0
        if not result["syntax_ok"]:
            result["command_output"] = "\n\n".join(outputs)[
                -MAX_COMMAND_OUTPUT_CHARS:
            ]
            return _fail(
                result,
                stage="syntax",
                code="RULE_LOAD_ERROR",
                message="Suricata 无法加载编译后的规则",
                retryable=True,
            )

        result["completed_stages"].append("syntax")
        result["validation_level"] = "syntax"
        expected_rule_sids = set(result["expected_sids"])
        rule_contract = _rule_scope_contract(static["rules"])
        positive_results: list[dict[str, object]] = []
        negative_results: list[dict[str, object]] = []

        for index, sample in enumerate(samples, start=1):
            name = str(_sample_field(sample, "name", f"sample-{index}"))
            expected = str(_sample_field(sample, "expected", "alert"))
            reason = str(_sample_field(sample, "reason", ""))
            pcap_value = _sample_field(sample, "pcap_path")
            if not isinstance(pcap_value, (str, Path)):
                return _fail(
                    result,
                    stage="samples",
                    code="SAMPLE_PCAP_REQUIRED",
                    message=f"样本 {name} 缺少 PCAP 路径",
                    retryable=False,
                )
            pcap_path = Path(pcap_value).resolve()
            if not pcap_path.is_file():
                return _fail(
                    result,
                    stage="samples",
                    code="SAMPLE_PCAP_NOT_FOUND",
                    message=f"样本 PCAP 不存在：{name}",
                    retryable=False,
                )
            # 保留文件名，便于测试桩、日志和失败样本按同一个名称关联。
            replay_pcap = temp_path / pcap_path.name
            try:
                shutil.copyfile(pcap_path, replay_pcap)
            except OSError as exc:
                return _fail(
                    result,
                    stage="samples",
                    code="SAMPLE_PCAP_READ_ERROR",
                    message=f"无法读取样本 PCAP {name}：{exc}",
                    retryable=False,
                )

            try:
                run_ok, matched_sids, output = run_suricata_on_pcap(
                    suricata_bin=executable,
                    config_path=runtime["config_path"],
                    rules_path=rules_path,
                    pcap_path=replay_pcap,
                    log_dir=temp_path / f"sample-{index:03d}",
                    timeout=replay_timeout,
                )
            except subprocess.TimeoutExpired:
                return _fail(
                    result,
                    stage="samples",
                    code="SURICATA_TIMEOUT",
                    message=f"样本回放超时：{name}",
                    retryable=False,
                )
            except OSError as exc:
                return _fail(
                    result,
                    stage="samples",
                    code="SURICATA_EXECUTION_ERROR",
                    message=f"样本回放失败 {name}：{exc}",
                    retryable=False,
                )
            outputs.append(f"===== sample: {name} =====\n{output}")
            if not run_ok:
                result["command_output"] = "\n\n".join(outputs)[
                    -MAX_COMMAND_OUTPUT_CHARS:
                ]
                return _fail(
                    result,
                    stage="samples",
                    code="SURICATA_REPLAY_ERROR",
                    message=f"Suricata 分析样本失败：{name}",
                    retryable=False,
                )

            configured_sids = _sample_field(sample, "expected_any_sids", ())
            if isinstance(configured_sids, Sequence) and not isinstance(
                configured_sids, (str, bytes)
            ):
                expected_sids = {
                    int(sid)
                    for sid in configured_sids
                    if isinstance(sid, int) or str(sid).isdigit()
                }
            else:
                expected_sids = set()
            if not expected_sids:
                expected_sids = _sample_expected_sids(
                    str(_sample_field(sample, "validates", "generic")),
                    expected_rule_sids,
                    rule_contract,
                )
            validates = str(_sample_field(sample, "validates", "generic"))
            if not expected_sids:
                # 本样本不适用于当前规则方向/scope；保留回放事实但不计入门槛。
                result["sample_results"].append(
                    {
                        "name": name,
                        "expected": expected,
                        "reason": reason,
                        "request_line": _sample_request_line(sample),
                        "validates": validates,
                        "expected_any_sids": [],
                        "matched_sids": matched_sids,
                        "passed": True,
                        "applicable": False,
                    }
                )
                continue

            matched_set = set(matched_sids)
            if expected == "no_alert":
                passed = not bool(matched_set & expected_sids)
            else:
                expected = "alert"
                passed = bool(matched_set & expected_sids)
            sample_result: dict[str, object] = {
                "name": name,
                "expected": expected,
                "reason": reason,
                "validates": validates,
                "request_line": _sample_request_line(sample),
                "expected_any_sids": sorted(expected_sids),
                "matched_sids": matched_sids,
                "passed": passed,
                "applicable": True,
            }
            result["sample_results"].append(sample_result)
            if expected == "alert":
                positive_results.append(sample_result)
                result["positive_matched_sids"] = sorted(
                    set(result["positive_matched_sids"]) | matched_set
                )
            else:
                negative_results.append(sample_result)
                result["negative_matched_sids"] = sorted(
                    set(result["negative_matched_sids"]) | matched_set
                )

    positive_passed = sum(bool(item["passed"]) for item in positive_results)
    result["positive_coverage"] = (
        positive_passed / len(positive_results) if positive_results else 0.0
    )
    false_positives = [item for item in negative_results if not item["passed"]]
    false_negatives = [item for item in positive_results if not item["passed"]]
    result["false_positive_count"] = len(false_positives)
    result["positive_match_ok"] = bool(positive_results) and not false_negatives
    result["negative_match_ok"] = (
        not false_positives if negative_results else None
    )
    result["command_output"] = "\n\n".join(outputs)[-MAX_COMMAND_OUTPUT_CHARS:]

    if positive_results and not false_negatives:
        result["completed_stages"].append("positive")
    if negative_results and not false_positives:
        result["completed_stages"].append("negative")
    if not positive_results:
        return _fail(
            result,
            stage="positive",
            code="POSITIVE_PCAP_REQUIRED",
            message="样本矩阵没有正向样本",
            retryable=False,
        )
    if not negative_results:
        result["warnings"].append("样本矩阵没有负样本，未评估误报")

    if false_negatives or false_positives:
        missing_names = [str(item["name"]) for item in false_negatives]
        false_positive_names = [str(item["name"]) for item in false_positives]
        if false_negatives and false_positives:
            code = "SAMPLE_MATRIX_MISMATCH"
        elif false_positives:
            code = "NEGATIVE_FALSE_POSITIVE"
        else:
            code = "NO_POSITIVE_MATCH"
        if missing_names:
            result["errors"].append(
                "正向变体未告警：" + "、".join(missing_names)
            )
        if false_positive_names:
            result["errors"].append(
                "近似负样本产生告警：" + "、".join(false_positive_names)
            )
        result["failed_stage"] = "samples"
        result["error_code"] = code
        result["retryable"] = True
        result["validation_level"] = "sample_matrix"
        return result

    result["passed"] = True
    result["validation_level"] = "sample_matrix"
    return result


def _fail(
    result: RuleValidationResult,
    *,
    stage: str,
    code: str,
    message: str,
    retryable: bool,
) -> RuleValidationResult:
    result["failed_stage"] = stage
    result["error_code"] = code
    result["retryable"] = retryable
    result["errors"].append(message)
    return result


def _find_executable(command: str) -> str | None:
    path = Path(command)
    if path.is_file():
        return str(path.resolve())
    return shutil.which(command)


def check_suricata_runtime(
    *,
    suricata_bin: str | None = None,
    config_path: str | None = None,
) -> SuricataRuntimeCheck:
    """在调用 LLM 前解析并检查 Suricata 验证环境。"""
    configured_bin = suricata_bin or os.getenv("SURICATA_BIN")
    if configured_bin:
        requested_bin = configured_bin
    elif (LOCAL_SURICATA_DIR / "suricata.exe").is_file():
        requested_bin = str(LOCAL_SURICATA_DIR / "suricata.exe")
    else:
        requested_bin = "suricata"

    executable = _find_executable(requested_bin)
    configured_config = config_path or os.getenv("SURICATA_CONFIG")
    if configured_config:
        requested_config = configured_config
    elif (LOCAL_SURICATA_DIR / "suricata.yaml").is_file():
        requested_config = str(LOCAL_SURICATA_DIR / "suricata.yaml")
    else:
        requested_config = "/etc/suricata/suricata.yaml"
    config_file = Path(requested_config)
    resolved_config = (
        str(config_file.resolve()) if config_file.is_file() else requested_config
    )

    if executable is None:
        return {
            "ok": False,
            "suricata_bin": None,
            "config_path": resolved_config,
            "error_code": "SURICATA_NOT_FOUND",
            "message": f"找不到 Suricata 可执行文件：{requested_bin}",
        }
    if not Path(resolved_config).is_file():
        return {
            "ok": False,
            "suricata_bin": executable,
            "config_path": resolved_config,
            "error_code": "SURICATA_CONFIG_NOT_FOUND",
            "message": f"Suricata 配置文件不存在：{resolved_config}",
        }
    return {
        "ok": True,
        "suricata_bin": executable,
        "config_path": resolved_config,
        "error_code": None,
        "message": None,
    }


def validate_suricata_rules(
    rules: str,
    *,
    positive_pcap_path: str | Path | None = None,
    negative_pcap_paths: list[str | Path] | None = None,
    require_positive: bool = True,
    policy: RulePolicy = DEFAULT_RULE_POLICY,
    suricata_bin: str | None = None,
    config_path: str | None = None,
    syntax_timeout: int = 30,
    replay_timeout: int = 60,
) -> RuleValidationResult:
    """验证项目策略、Suricata 规则加载以及 PCAP 的预期行为。"""
    static = static_check_rules(rules, policy=policy)
    result = _initial_result(static["expected_sids"])

    if not static["passed"]:
        result["errors"].extend(static["errors"])
        result["failed_stage"] = "static"
        result["error_code"] = "STATIC_RULE_ERROR"
        result["retryable"] = True
        return result

    result["completed_stages"].append("static")
    result["validation_level"] = "static"

    if require_positive and positive_pcap_path is None:
        return _fail(
            result,
            stage="positive",
            code="POSITIVE_PCAP_REQUIRED",
            message="完整验证必须提供正向 PCAP",
            retryable=False,
        )

    runtime = check_suricata_runtime(
        suricata_bin=suricata_bin,
        config_path=config_path,
    )
    if not runtime["ok"]:
        return _fail(
            result,
            stage="syntax",
            code=runtime["error_code"] or "SURICATA_RUNTIME_ERROR",
            message=runtime["message"] or "Suricata 运行环境不可用",
            retryable=False,
        )
    executable = runtime["suricata_bin"]
    resolved_config = runtime["config_path"]
    assert executable is not None

    outputs: list[str] = []
    negative_paths = [Path(path).resolve() for path in (negative_pcap_paths or [])]

    with _shared_temporary_directory("suricata-validation-") as temp_dir:
        temp_path = Path(temp_dir)
        rules_path = temp_path / "generated.rules"
        syntax_log_dir = temp_path / "syntax-logs"
        syntax_log_dir.mkdir(parents=True, exist_ok=True)
        rules_path.write_text(static["rules"] + "\n", encoding="utf-8")

        try:
            syntax_process, _ = _run_suricata_command(
                [
                    executable,
                    "-T",
                    "-c",
                    resolved_config,
                    "-S",
                    str(rules_path),
                    "-l",
                    str(syntax_log_dir),
                ],
                timeout=syntax_timeout,
                log_dir=syntax_log_dir,
            )
        except subprocess.TimeoutExpired:
            return _fail(
                result,
                stage="syntax",
                code="SURICATA_TIMEOUT",
                message="Suricata 语法验证超时",
                retryable=False,
            )
        except OSError as exc:
            return _fail(
                result,
                stage="syntax",
                code="SURICATA_EXECUTION_ERROR",
                message=f"无法执行 Suricata：{exc}",
                retryable=False,
            )

        outputs.append("===== syntax =====\n" + _command_output(syntax_process))
        result["syntax_ok"] = syntax_process.returncode == 0
        if not result["syntax_ok"]:
            result["command_output"] = "\n\n".join(outputs)
            return _fail(
                result,
                stage="syntax",
                code="RULE_LOAD_ERROR",
                message="Suricata 无法加载生成的规则",
                retryable=True,
            )

        result["completed_stages"].append("syntax")
        result["validation_level"] = "syntax"

        if positive_pcap_path is not None:
            positive_path = Path(positive_pcap_path).resolve()
            if not positive_path.is_file():
                result["positive_match_ok"] = False
                return _fail(
                    result,
                    stage="positive",
                    code="POSITIVE_PCAP_NOT_FOUND",
                    message=f"正向 PCAP 不存在：{positive_path}",
                    retryable=False,
                )

            try:
                run_ok, matched_sids, output = run_suricata_on_pcap(
                    suricata_bin=executable,
                    config_path=resolved_config,
                    rules_path=rules_path,
                    pcap_path=positive_path,
                    log_dir=temp_path / "positive-logs",
                    timeout=replay_timeout,
                )
            except subprocess.TimeoutExpired:
                result["positive_match_ok"] = False
                return _fail(
                    result,
                    stage="positive",
                    code="SURICATA_TIMEOUT",
                    message="正向 PCAP 回放超时",
                    retryable=False,
                )
            except OSError as exc:
                result["positive_match_ok"] = False
                return _fail(
                    result,
                    stage="positive",
                    code="SURICATA_EXECUTION_ERROR",
                    message=f"正向 PCAP 回放失败：{exc}",
                    retryable=False,
                )

            outputs.append("===== positive =====\n" + output)
            result["positive_matched_sids"] = matched_sids
            matched_set = set(matched_sids)
            expected_set = set(result["expected_sids"])
            if policy.positive_match_mode == "all":
                match_ok = expected_set.issubset(matched_set)
            else:
                match_ok = bool(expected_set & matched_set)
            result["positive_match_ok"] = run_ok and match_ok

            if not run_ok:
                result["command_output"] = "\n\n".join(outputs)
                return _fail(
                    result,
                    stage="positive",
                    code="SURICATA_REPLAY_ERROR",
                    message="Suricata 分析正向 PCAP 时执行失败",
                    retryable=False,
                )
            if not match_ok:
                result["command_output"] = "\n\n".join(outputs)
                missing = sorted(expected_set - matched_set)
                return _fail(
                    result,
                    stage="positive",
                    code="NO_POSITIVE_MATCH",
                    message=f"正向 PCAP 未命中预期 SID：{missing}",
                    retryable=True,
                )

            result["completed_stages"].append("positive")
            result["validation_level"] = "positive"
        elif negative_paths:
            return _fail(
                result,
                stage="negative",
                code="POSITIVE_REQUIRED_FOR_NEGATIVE",
                message="必须先通过正向回放，才能确认告警输出并评估反向 PCAP",
                retryable=False,
            )

        if negative_paths:
            all_negative_sids: set[int] = set()
            expected_set = set(result["expected_sids"])
            for index, pcap_path in enumerate(negative_paths, start=1):
                if not pcap_path.is_file():
                    result["negative_match_ok"] = False
                    return _fail(
                        result,
                        stage="negative",
                        code="NEGATIVE_PCAP_NOT_FOUND",
                        message=f"反向 PCAP 不存在：{pcap_path}",
                        retryable=False,
                    )
                try:
                    run_ok, matched_sids, output = run_suricata_on_pcap(
                        suricata_bin=executable,
                        config_path=resolved_config,
                        rules_path=rules_path,
                        pcap_path=pcap_path,
                        log_dir=temp_path / f"negative-logs-{index}",
                        timeout=replay_timeout,
                    )
                except subprocess.TimeoutExpired:
                    result["negative_match_ok"] = False
                    return _fail(
                        result,
                        stage="negative",
                        code="SURICATA_TIMEOUT",
                        message=f"反向 PCAP 回放超时：{pcap_path}",
                        retryable=False,
                    )
                except OSError as exc:
                    result["negative_match_ok"] = False
                    return _fail(
                        result,
                        stage="negative",
                        code="SURICATA_EXECUTION_ERROR",
                        message=f"反向 PCAP 回放失败：{exc}",
                        retryable=False,
                    )

                outputs.append(f"===== negative: {pcap_path} =====\n{output}")
                if not run_ok:
                    result["command_output"] = "\n\n".join(outputs)
                    result["negative_match_ok"] = False
                    return _fail(
                        result,
                        stage="negative",
                        code="SURICATA_REPLAY_ERROR",
                        message=f"Suricata 分析反向 PCAP 失败：{pcap_path}",
                        retryable=False,
                    )
                all_negative_sids.update(matched_sids)

            result["negative_matched_sids"] = sorted(all_negative_sids)
            false_positive_sids = sorted(expected_set & all_negative_sids)
            result["negative_match_ok"] = not false_positive_sids
            if false_positive_sids:
                result["command_output"] = "\n\n".join(outputs)
                return _fail(
                    result,
                    stage="negative",
                    code="NEGATIVE_FALSE_POSITIVE",
                    message=f"反向 PCAP 触发生成规则，SID：{false_positive_sids}",
                    retryable=True,
                )

            result["completed_stages"].append("negative")
            result["validation_level"] = "positive_and_negative"
        else:
            result["warnings"].append("没有提供反向 PCAP，未评估误报")

    result["passed"] = True
    result["command_output"] = "\n\n".join(outputs)[-MAX_COMMAND_OUTPUT_CHARS:]
    return result
