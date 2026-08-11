"""Stable command-line entrypoint for the production E-direct pipeline."""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
from collections.abc import Sequence
from typing import Any

from production import PIPELINE_ID, WorkflowConfig, run_generation


def _case_input(case: dict[str, Any], key: str, case_dir: Path) -> str | bytes:
    path_value = case.get(f"{key}_path")
    if path_value:
        path = Path(path_value)
        if not path.is_absolute():
            path = case_dir / path
        return path.read_bytes()
    value = case.get(key, "")
    if not isinstance(value, str):
        raise ValueError(f"{key} 必须是字符串，或通过 {key}_path 指向文件")
    return value


def _case_paths(values: Sequence[str], case_dir: Path) -> list[str]:
    paths: list[str] = []
    for value in values:
        path = Path(value)
        if not path.is_absolute():
            path = case_dir / path
        paths.append(str(path))
    return paths


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="运行 E Direct Generate -> Execute -> Repair -> Verify 主链")
    parser.add_argument("case", type=Path, help="JSON 格式的检测案例")
    parser.add_argument("--output-dir", type=Path, default=Path("artifacts"))
    parser.add_argument("--sid-start", type=int, default=123)
    parser.add_argument("--max-attempts", type=int, default=3)
    parser.add_argument("--suricata-bin", default=os.getenv("SURICATA_BIN"))
    parser.add_argument("--suricata-config", default=os.getenv("SURICATA_CONFIG"))
    parser.add_argument("--ruleops-store", type=Path, default=Path(os.getenv("RULEOPS_STORE", "artifacts/rule-kb.json")))
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    case_path = args.case.resolve()
    case = json.loads(case_path.read_text(encoding="utf-8"))
    config = WorkflowConfig(
        sid_start=args.sid_start,
        max_rule_attempts=args.max_attempts,
        suricata_bin=args.suricata_bin,
        suricata_config=args.suricata_config,
        ruleops_path=str(args.ruleops_store.resolve()),
    )
    python_poc = _case_input(case, "python_poc", case_path.parent)
    python_poc_path = case.get("python_poc_path")
    result = run_generation(
        case_id=str(case.get("case_id", case_path.stem)),
        base=str(case.get("base", "")),
        poc=str(case.get("poc", "")),
        http_request=_case_input(case, "http_request", case_path.parent),
        http_response=_case_input(case, "http_response", case_path.parent),
        python_poc=python_poc,
        python_poc_filename=Path(str(python_poc_path)).name if python_poc_path else str(case.get("python_poc_filename", "poc.py")),
        negative_pcap_paths=_case_paths(case.get("negative_pcap_paths", []), case_path.parent),
        output_dir=args.output_dir,
        config=config,
    )
    summary = {key: result.get(key) for key in ("status", "attempt", "pcap_path", "rules_path", "report_path", "failure_code", "failure_message")}
    summary.update({"pipeline": PIPELINE_ID, "pipeline_id": PIPELINE_ID, "explanation": result.get("explanation"), "ruleops": result.get("ruleops")})
    print(json.dumps(summary, ensure_ascii=False, indent=2))
    return 0 if result.get("status") == "passed" else 1


__all__ = ["main"]
