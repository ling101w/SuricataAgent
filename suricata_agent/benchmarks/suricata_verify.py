"""Run a focused HTTP benchmark from the indexed OISF suricata-verify suite."""

from __future__ import annotations

import argparse
import csv
import json
import re
import shlex
import subprocess
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from suricata_agent.services.suricata import (
    _run_suricata_command,
    check_suricata_runtime,
    run_command,
)


PROJECT_DIR = Path(__file__).resolve().parents[2]
DEFAULT_MANIFEST = PROJECT_DIR / "benchmarks" / "suricata-verify-manifest.json"
DEFAULT_CASES = (
    "base64",
    "detect-absent-http-request-body",
    "http-double-encoded-uri",
    "http-encoding-gzip-uncompressed",
    "http-multiple-cl",
    "http-post-data-decompression",
    "http-raw-header",
    "http-request-header-multi",
    "http-request-invalid",
    "http-uri-spaces",
    "http-urldecode-body",
    "http2-keywords",
)
VERSION_RE = re.compile(r"Suricata version\s+(\d+)\.(\d+)\.(\d+)")


def _version_tuple(value: str) -> tuple[int, int, int]:
    parts = value.split(".")
    parsed = [int(part) for part in parts[:3]]
    return tuple((parsed + [0, 0, 0])[:3])  # type: ignore[return-value]


def _read_version(executable: str) -> tuple[str, tuple[int, int, int]]:
    process = run_command([executable, "-V"], timeout=30)
    output = "\n".join((process.stdout, process.stderr))
    match = VERSION_RE.search(output)
    if process.returncode != 0 or not match:
        raise RuntimeError("Unable to determine the Suricata version")
    raw = ".".join(match.groups())
    return raw, tuple(int(part) for part in match.groups())


def _requirements_met(
    requires: object, version: tuple[int, int, int]
) -> tuple[bool, str | None]:
    if not isinstance(requires, dict):
        return True, None
    if requires.get("features"):
        return False, "feature requirements are not supported by this smoke runner"
    if requires.get("os"):
        return False, "OS-specific test"
    minimum = requires.get("min-version")
    if minimum is not None and version < _version_tuple(str(minimum)):
        return False, f"requires Suricata >= {minimum}"
    maximum = requires.get("lt-version")
    if maximum is not None and version >= _version_tuple(str(maximum)):
        return False, f"requires Suricata < {maximum}"
    exact = requires.get("version")
    if exact is not None:
        required = str(exact)
        actual = ".".join(str(part) for part in version)
        if not actual.startswith(required + ".") and actual != required:
            return False, f"requires Suricata {required}"
    return True, None


def _case_args(value: object) -> tuple[list[str], str | None]:
    if not isinstance(value, list):
        return [], None
    arguments: list[str] = []
    for item in value:
        if not isinstance(item, str):
            return [], "non-string Suricata argument"
        arguments.extend(shlex.split(item, posix=True))
    if arguments not in ([], ["-k", "none"]):
        return [], "custom Suricata arguments are outside the smoke-runner contract"
    return arguments, None


def _read_alerts(path: Path) -> tuple[Counter[str], Counter[str]]:
    sid_counts: Counter[str] = Counter()
    signature_counts: Counter[str] = Counter()
    eve_path = path / "eve.json"
    if not eve_path.is_file():
        return sid_counts, signature_counts
    with eve_path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                continue
            if event.get("event_type") != "alert":
                continue
            alert = event.get("alert")
            if not isinstance(alert, dict):
                continue
            sid = alert.get("signature_id")
            if isinstance(sid, (int, str)):
                sid_counts[str(sid)] += 1
            signature = alert.get("signature")
            if isinstance(signature, str):
                signature_counts[signature] += 1
    return sid_counts, signature_counts


def _oracle_results(
    oracles: object,
    sid_counts: Counter[str],
    signature_counts: Counter[str],
) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    if not isinstance(oracles, list):
        return results
    for oracle in oracles:
        if not isinstance(oracle, dict) or not isinstance(oracle.get("count"), int):
            continue
        expected = oracle["count"]
        if "sid" in oracle:
            key = str(oracle["sid"])
            actual = sid_counts[key]
            field = "sid"
        elif isinstance(oracle.get("signature"), str):
            key = oracle["signature"]
            actual = signature_counts[key]
            field = "signature"
        else:
            key = "all-alerts"
            actual = sum(sid_counts.values())
            field = "event_type"
        results.append(
            {
                "field": field,
                "value": key,
                "expected_count": expected,
                "actual_count": actual,
                "passed": actual == expected,
            }
        )
    return results


def run_group(
    manifest_path: Path,
    case_ids: tuple[str, ...],
    output_dir: Path,
    *,
    suricata_bin: str | None = None,
    suricata_config: str | None = None,
) -> dict[str, Any]:
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    source_path = manifest.get("source", {}).get("path")
    if not isinstance(source_path, str):
        raise ValueError("Manifest source.path is missing")
    source_root = (PROJECT_DIR / source_path).resolve()
    indexed = {case["case_id"]: case for case in manifest.get("cases", [])}
    missing = [case_id for case_id in case_ids if case_id not in indexed]
    if missing:
        raise ValueError("Unknown benchmark cases: " + ", ".join(missing))
    if output_dir.exists():
        raise ValueError(f"Output directory already exists: {output_dir}")
    output_dir.mkdir(parents=True)

    runtime = check_suricata_runtime(
        suricata_bin=suricata_bin,
        config_path=suricata_config,
    )
    if not runtime["ok"] or runtime["suricata_bin"] is None:
        raise RuntimeError(runtime["message"] or "Suricata runtime is unavailable")
    executable = runtime["suricata_bin"]
    config_path = runtime["config_path"]
    version_text, version = _read_version(executable)

    results: list[dict[str, Any]] = []
    for case_id in case_ids:
        case = indexed[case_id]
        requirements_ok, skip_reason = _requirements_met(case.get("requires"), version)
        extra_args, args_error = _case_args(case.get("args"))
        pcaps = case.get("pcaps", [])
        rules = case.get("rules", [])
        case_result: dict[str, Any] = {
            "case_id": case_id,
            "status": "pending",
            "passed": False,
            "skip_reason": None,
            "syntax_ok": False,
            "replay_ok": False,
            "oracle_passed": 0,
            "oracle_total": 0,
            "oracles": [],
        }
        if not requirements_ok or args_error:
            case_result["status"] = "skipped"
            case_result["skip_reason"] = skip_reason or args_error
            results.append(case_result)
            continue
        if len(pcaps) != 1 or not rules:
            case_result["status"] = "skipped"
            case_result["skip_reason"] = "smoke runner requires one PCAP and at least one rule file"
            results.append(case_result)
            continue

        case_dir = output_dir / case_id.replace("/", "__")
        case_dir.mkdir(parents=True)
        case_config = config_path
        compatibility_args: list[str] = []
        indexed_config = case.get("config")
        if isinstance(indexed_config, dict) and isinstance(indexed_config.get("path"), str):
            case_config = str(source_root / indexed_config["path"])
            portable_config_dir = Path(config_path).resolve().parent
            support_files = {
                "classification-file": portable_config_dir / "classification.config",
                "reference-config-file": portable_config_dir / "reference.config",
            }
            for setting, path in support_files.items():
                if path.is_file():
                    compatibility_args.extend(("--set", f"{setting}={path}"))
        case_result["config_path"] = str(Path(case_config).resolve())
        combined_rules = case_dir / "oracle.rules"
        combined_rules.write_text(
            "\n".join(
                (source_root / item["path"]).read_text(encoding="utf-8", errors="replace")
                for item in rules
            )
            + "\n",
            encoding="utf-8",
        )
        syntax_dir = case_dir / "syntax"
        syntax_dir.mkdir()
        try:
            syntax, _ = _run_suricata_command(
                [
                    executable,
                    "-T",
                    "-c",
                    case_config,
                    "-S",
                    str(combined_rules),
                    "-l",
                    str(syntax_dir),
                    *extra_args,
                    *compatibility_args,
                ],
                timeout=60,
                log_dir=syntax_dir,
            )
        except subprocess.TimeoutExpired:
            case_result["status"] = "failed"
            case_result["error"] = "syntax timeout after retry"
            results.append(case_result)
            continue
        case_result["syntax_ok"] = syntax.returncode == 0
        (case_dir / "syntax-output.txt").write_text(
            "\n".join((syntax.stdout, syntax.stderr)), encoding="utf-8"
        )
        if syntax.returncode != 0:
            case_result["status"] = "failed"
            results.append(case_result)
            continue

        replay_dir = case_dir / "replay"
        replay_dir.mkdir()
        pcap_path = source_root / pcaps[0]["path"]
        try:
            replay, actual_replay_dir = _run_suricata_command(
                [
                    executable,
                    "-c",
                    case_config,
                    "-S",
                    str(combined_rules),
                    "-r",
                    str(pcap_path),
                    "-l",
                    str(replay_dir),
                    *extra_args,
                    *compatibility_args,
                ],
                timeout=120,
                log_dir=replay_dir,
            )
        except subprocess.TimeoutExpired:
            case_result["status"] = "failed"
            case_result["error"] = "replay timeout after retry"
            results.append(case_result)
            continue
        case_result["replay_ok"] = replay.returncode == 0
        (case_dir / "replay-output.txt").write_text(
            "\n".join((replay.stdout, replay.stderr)), encoding="utf-8"
        )
        if replay.returncode != 0:
            case_result["status"] = "failed"
            results.append(case_result)
            continue

        sid_counts, signature_counts = _read_alerts(actual_replay_dir)
        oracle_results = _oracle_results(
            case.get("alert_oracle"), sid_counts, signature_counts
        )
        case_result["oracles"] = oracle_results
        case_result["oracle_total"] = len(oracle_results)
        case_result["oracle_passed"] = sum(item["passed"] for item in oracle_results)
        case_result["matched_sids"] = dict(sorted(sid_counts.items()))
        case_result["passed"] = bool(oracle_results) and all(
            item["passed"] for item in oracle_results
        )
        case_result["status"] = "passed" if case_result["passed"] else "failed"
        results.append(case_result)

    summary = {
        "requested": len(case_ids),
        "passed": sum(item["status"] == "passed" for item in results),
        "failed": sum(item["status"] == "failed" for item in results),
        "skipped": sum(item["status"] == "skipped" for item in results),
    }
    summary["pass_rate"] = round(summary["passed"] / summary["requested"], 6)
    report = {
        "version": 1,
        "suite": manifest.get("name"),
        "source_commit": manifest.get("source", {}).get("commit"),
        "suricata_version": version_text,
        "created_at": datetime.now(UTC).isoformat(),
        "summary": summary,
        "results": results,
    }
    (output_dir / "report.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    with (output_dir / "report.csv").open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=(
                "case_id",
                "status",
                "syntax_ok",
                "replay_ok",
                "oracle_passed",
                "oracle_total",
                "skip_reason",
            ),
        )
        writer.writeheader()
        writer.writerows({key: item.get(key) for key in writer.fieldnames} for item in results)
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--output-dir", type=Path)
    parser.add_argument("--cases", nargs="*")
    parser.add_argument("--suricata-bin")
    parser.add_argument("--suricata-config")
    args = parser.parse_args()
    output_dir = args.output_dir or PROJECT_DIR / "benchmark-artifacts" / (
        "suricata-verify-smoke-" + datetime.now().strftime("%Y%m%d-%H%M%S")
    )
    case_ids = tuple(args.cases) if args.cases else DEFAULT_CASES
    report = run_group(
        args.manifest.resolve(),
        case_ids,
        output_dir.resolve(),
        suricata_bin=args.suricata_bin,
        suricata_config=args.suricata_config,
    )
    print(json.dumps(report["summary"], ensure_ascii=False, indent=2))
    return 1 if report["summary"]["failed"] else 0


if __name__ == "__main__":
    raise SystemExit(main())
