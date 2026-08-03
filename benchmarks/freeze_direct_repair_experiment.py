"""Freeze and verify the paired Direct validation/repair v1 experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from benchmarks.benchmark import (  # noqa: E402
    REPAIR_FEEDBACK_SAMPLES,
    REPAIR_HOLDOUT_SAMPLES,
)
from benchmarks.summary import build_summary, write_summary  # noqa: E402


DEFAULT_DATASET_MANIFEST = PROJECT_DIR / "benchmarks" / "v0-manifest.json"
DEFAULT_RESULTS = PROJECT_DIR / "benchmarks" / "results"
DEFAULT_OUTPUT = PROJECT_DIR / "benchmarks" / "experiments" / "direct-repair-v1"
EXPERIMENT_SYSTEMS = (
    "direct_llm",
    "compiler",
    "full_agent",
    "direct_validator",
    "direct_repair",
)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    return path.resolve().relative_to(PROJECT_DIR).as_posix()


def _case_ids(dataset_manifest: Path) -> list[str]:
    value = json.loads(dataset_manifest.read_text(encoding="utf-8"))
    cases = [str(item["case_id"]) for item in value.get("cases", [])]
    if value.get("version") != 1 or value.get("split") != "dev" or len(cases) != 12:
        raise ValueError("unsupported Benchmark v0 manifest")
    return cases


def _load_results(results_root: Path, case_ids: list[str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for system in EXPERIMENT_SYSTEMS:
        for case_id in case_ids:
            path = results_root / system / case_id / "result.json"
            if not path.is_file():
                raise FileNotFoundError(f"missing experiment result: {path}")
            result = json.loads(path.read_text(encoding="utf-8"))
            if result.get("system") != system or result.get("case_id") != case_id:
                raise ValueError(f"experiment result identity mismatch: {path}")
            results.append(result)
    return results


def freeze_experiment(
    dataset_manifest: Path = DEFAULT_DATASET_MANIFEST,
    results_root: Path = DEFAULT_RESULTS,
    output_root: Path = DEFAULT_OUTPUT,
) -> dict[str, Any]:
    dataset_manifest = dataset_manifest.resolve()
    results_root = results_root.resolve()
    output_root = output_root.resolve()
    freeze_path = output_root / "freeze-manifest.json"
    if freeze_path.exists():
        return verify_experiment(dataset_manifest, results_root, output_root)

    case_ids = _case_ids(dataset_manifest)
    results = _load_results(results_root, case_ids)
    output_root.mkdir(parents=True, exist_ok=False)
    rules_root = output_root / "direct-repair-rules"
    rules_root.mkdir()

    source_results: list[dict[str, str]] = []
    frozen_rules: list[dict[str, str]] = []
    for system in EXPERIMENT_SYSTEMS:
        for case_id in case_ids:
            result_path = results_root / system / case_id / "result.json"
            source_results.append(
                {"path": _relative(result_path), "sha256": _sha256(result_path)}
            )
            if system != "direct_repair":
                continue
            source_rule = result_path.parent / "generated.rules"
            frozen_rule = rules_root / f"{case_id}.rules"
            shutil.copyfile(source_rule, frozen_rule)
            frozen_rules.append(
                {
                    "case_id": case_id,
                    "path": _relative(frozen_rule),
                    "sha256": _sha256(frozen_rule),
                    "source_path": _relative(source_rule),
                    "source_sha256": _sha256(source_rule),
                }
            )

    summary = build_summary(results)
    write_summary(summary, output_root)
    manifest = {
        "version": 1,
        "name": "suricataagent-direct-validation-repair-v1",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "dataset_manifest": {
            "path": _relative(dataset_manifest),
            "sha256": _sha256(dataset_manifest),
        },
        "systems": list(EXPERIMENT_SYSTEMS),
        "case_count": len(case_ids),
        "result_count": len(results),
        "protocol": {
            "paired_initial_system": "direct_llm",
            "direct_validator_reuses_initial_rule_and_validation": True,
            "repair_feedback_samples": list(REPAIR_FEEDBACK_SAMPLES),
            "heldout_samples": list(REPAIR_HOLDOUT_SAMPLES),
            "max_total_attempts": 3,
        },
        "source_results": source_results,
        "direct_repair_rules": frozen_rules,
        "artifacts": {
            name: _sha256(output_root / name)
            for name in ("summary.json", "summary.csv", "results.csv")
        },
    }
    freeze_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def verify_experiment(
    dataset_manifest: Path = DEFAULT_DATASET_MANIFEST,
    results_root: Path = DEFAULT_RESULTS,
    output_root: Path = DEFAULT_OUTPUT,
) -> dict[str, Any]:
    dataset_manifest = dataset_manifest.resolve()
    results_root = results_root.resolve()
    output_root = output_root.resolve()
    freeze_path = output_root / "freeze-manifest.json"
    manifest = json.loads(freeze_path.read_text(encoding="utf-8"))
    if _sha256(dataset_manifest) != manifest["dataset_manifest"]["sha256"]:
        raise ValueError("Benchmark v0 dataset changed after experiment freeze")
    for item in manifest["source_results"]:
        path = PROJECT_DIR / item["path"]
        if not path.is_file() or _sha256(path) != item["sha256"]:
            raise ValueError(f"experiment source result changed: {path}")
    for item in manifest["direct_repair_rules"]:
        frozen_rule = PROJECT_DIR / item["path"]
        source_rule = PROJECT_DIR / item["source_path"]
        if not frozen_rule.is_file() or _sha256(frozen_rule) != item["sha256"]:
            raise ValueError(f"frozen Direct repair rule changed: {frozen_rule}")
        if not source_rule.is_file() or _sha256(source_rule) != item["source_sha256"]:
            raise ValueError(f"source Direct repair rule changed: {source_rule}")
    for name, expected_hash in manifest["artifacts"].items():
        path = output_root / name
        if not path.is_file() or _sha256(path) != expected_hash:
            raise ValueError(f"frozen experiment artifact changed: {path}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-manifest", type=Path, default=DEFAULT_DATASET_MANIFEST)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    operation = verify_experiment if args.verify else freeze_experiment
    result = operation(args.dataset_manifest, args.results, args.output)
    print(
        json.dumps(
            {
                "experiment": str(args.output.resolve()),
                "case_count": result["case_count"],
                "result_count": result["result_count"],
                "verified": True,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
