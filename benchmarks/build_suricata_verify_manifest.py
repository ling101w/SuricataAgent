"""Index HTTP alert tests from an OISF suricata-verify checkout."""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

import yaml


PROJECT_DIR = Path(__file__).resolve().parents[1]
DEFAULT_SOURCE = PROJECT_DIR / "benchmarks" / "suricata-verify"
DEFAULT_OUTPUT = PROJECT_DIR / "benchmarks" / "suricata-verify-manifest.json"
REPOSITORY = "https://github.com/OISF/suricata-verify.git"
HTTP_ACTION = re.compile(
    r"^\s*(?:alert|drop|reject|pass)\s+(?:http|http2)\b", re.IGNORECASE | re.MULTILINE
)
RULE_ACTION = re.compile(
    r"^\s*(?:alert|drop|reject|pass)\s+\w+\b", re.IGNORECASE | re.MULTILINE
)
HTTP_KEYWORD = re.compile(r"\bhttp(?:[._][a-z][a-z0-9_.-]*)", re.IGNORECASE)


def _git(source: Path, *args: str) -> str:
    process = subprocess.run(
        ["git", *args],
        cwd=source,
        check=True,
        capture_output=True,
        text=True,
    )
    return process.stdout.strip()


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative_asset(source: Path, path: Path) -> dict[str, Any]:
    return {
        "path": path.relative_to(source).as_posix(),
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
    }


def _configured_paths(test_dir: Path, value: object) -> list[Path]:
    if isinstance(value, str) and value.strip():
        return [(test_dir / value).resolve()]
    if isinstance(value, Sequence) and not isinstance(value, (str, bytes)):
        return [
            (test_dir / item).resolve()
            for item in value
            if isinstance(item, str) and item.strip()
        ]
    return []


def _resolve_pcaps(test_dir: Path, config: Mapping[str, Any]) -> list[Path]:
    if "pcap" in config:
        return _configured_paths(test_dir, config.get("pcap"))
    return sorted((*test_dir.glob("*.pcap"), *test_dir.glob("*.pcapng")))


def _resolve_rules(test_dir: Path, config: Mapping[str, Any]) -> list[Path]:
    configured = _configured_paths(test_dir, config.get("rules"))
    if configured:
        return configured
    return sorted((*test_dir.glob("*.rules"), *test_dir.glob("*.rule")))


def _has_http_rule(rule_paths: Sequence[Path]) -> bool:
    for path in rule_paths:
        text = path.read_text(encoding="utf-8", errors="replace")
        if HTTP_ACTION.search(text):
            return True
        if RULE_ACTION.search(text) and HTTP_KEYWORD.search(text):
            return True
    return False


def _alert_oracles(config: Mapping[str, Any]) -> list[dict[str, Any]]:
    checks = config.get("checks")
    if not isinstance(checks, Sequence) or isinstance(checks, (str, bytes)):
        return []
    oracles: list[dict[str, Any]] = []
    for check in checks:
        if not isinstance(check, Mapping):
            continue
        filter_config = check.get("filter")
        if not isinstance(filter_config, Mapping):
            continue
        match = filter_config.get("match")
        if not isinstance(match, Mapping) or match.get("event_type") != "alert":
            continue
        count = filter_config.get("count")
        if not isinstance(count, int) or count < 0:
            continue
        oracle: dict[str, Any] = {"count": count}
        sid = match.get("alert.signature_id")
        if isinstance(sid, (int, str)):
            oracle["sid"] = sid
        signature = match.get("alert.signature")
        if isinstance(signature, str):
            oracle["signature"] = signature
        oracles.append(oracle)
    return oracles


def build_manifest(source: Path) -> dict[str, Any]:
    source = source.resolve()
    if not (source / ".git").is_dir():
        raise ValueError(f"Not a suricata-verify Git checkout: {source}")
    tests_root = source / "tests"
    if not tests_root.is_dir():
        raise ValueError(f"Missing tests directory: {tests_root}")

    stats = {
        "descriptors": 0,
        "with_resolved_pcap": 0,
        "with_resolved_rules": 0,
        "with_http_rules": 0,
        "with_structured_alert_oracle": 0,
        "selected": 0,
    }
    cases: list[dict[str, Any]] = []
    for descriptor in sorted(tests_root.rglob("test.yaml")):
        stats["descriptors"] += 1
        loaded = yaml.safe_load(descriptor.read_text(encoding="utf-8"))
        if not isinstance(loaded, Mapping):
            continue
        config = dict(loaded)
        test_dir = descriptor.parent
        pcaps = _resolve_pcaps(test_dir, config)
        rules = _resolve_rules(test_dir, config)
        pcaps_valid = bool(pcaps) and all(path.is_file() for path in pcaps)
        rules_valid = bool(rules) and all(path.is_file() for path in rules)
        if pcaps_valid:
            stats["with_resolved_pcap"] += 1
        if rules_valid:
            stats["with_resolved_rules"] += 1
        http_rules = rules_valid and _has_http_rule(rules)
        if http_rules:
            stats["with_http_rules"] += 1
        oracles = _alert_oracles(config)
        if oracles:
            stats["with_structured_alert_oracle"] += 1
        if not (pcaps_valid and rules_valid and http_rules and oracles):
            continue

        case_id = test_dir.relative_to(tests_root).as_posix()
        configuration = test_dir / "suricata.yaml"
        positive_sids = sorted(
            {str(item["sid"]) for item in oracles if item["count"] > 0 and "sid" in item}
        )
        negative_sids = sorted(
            {str(item["sid"]) for item in oracles if item["count"] == 0 and "sid" in item}
        )
        readme = test_dir / "README.md"
        cases.append(
            {
                "case_id": case_id,
                "test_path": test_dir.relative_to(source).as_posix(),
                "descriptor": descriptor.relative_to(source).as_posix(),
                "pcaps": [_relative_asset(source, path) for path in pcaps],
                "rules": [_relative_asset(source, path) for path in rules],
                "config": (
                    _relative_asset(source, configuration)
                    if configuration.is_file()
                    else None
                ),
                "readme": readme.relative_to(source).as_posix() if readme.is_file() else None,
                "alert_oracle": oracles,
                "positive_sids": positive_sids,
                "negative_sids": negative_sids,
                "requires": config.get("requires", {}),
                "args": config.get("args", []),
            }
        )

    stats["selected"] = len(cases)
    return {
        "version": 1,
        "name": "suricata-verify-http-alert-benchmark",
        "selection": (
            "Tests with a resolved PCAP, resolved rules containing HTTP detection "
            "semantics, and at least one structured EVE alert check."
        ),
        "source": {
            "repository": REPOSITORY,
            "resolved_remote": _git(source, "remote", "get-url", "origin"),
            "commit": _git(source, "rev-parse", "HEAD"),
            "path": source.relative_to(PROJECT_DIR).as_posix(),
        },
        "stats": stats,
        "cases": cases,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=DEFAULT_SOURCE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    manifest = build_manifest(args.source)
    args.output.resolve().write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    print(json.dumps(manifest["stats"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
