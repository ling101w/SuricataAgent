"""Freeze and verify the paired semantic-intent F/G experiment."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
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
    materialize_posthoc_rule_ir,
)
from benchmarks.summary import build_summary, write_summary  # noqa: E402
from semantic_generation import (  # noqa: E402
    DIAGNOSIS_REPAIR_SYSTEM_PROMPT,
    INTENT_RULE_SYSTEM_PROMPT,
    INTENT_SYSTEM_PROMPT,
    REPAIR_DIAGNOSIS_SYSTEM_PROMPT,
)


DEFAULT_DATASET_MANIFEST = PROJECT_DIR / "benchmarks" / "v0-manifest.json"
DEFAULT_RESULTS = PROJECT_DIR / "benchmarks" / "results"
DEFAULT_OUTPUT = PROJECT_DIR / "benchmarks" / "experiments" / "semantic-intent-repair-v1"
EXPERIMENT_SYSTEMS = (
    "direct_llm",
    "direct_repair",
    "semantic_intent",
    "semantic_intent_repair",
)
SEMANTIC_SYSTEMS = frozenset({"semantic_intent", "semantic_intent_repair"})


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


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

    source_results: list[dict[str, str]] = []
    frozen_artifacts: list[dict[str, str]] = []
    for system in EXPERIMENT_SYSTEMS:
        for case_id in case_ids:
            result_path = results_root / system / case_id / "result.json"
            source_results.append(
                {"path": _relative(result_path), "sha256": _sha256(result_path)}
            )
            if system not in SEMANTIC_SYSTEMS:
                continue
            source_root = result_path.parent
            destination_root = output_root / system / case_id
            destination_root.mkdir(parents=True)
            for name in ("generated.rules", "detection-intent.json"):
                source = source_root / name
                destination = destination_root / name
                shutil.copyfile(source, destination)
                frozen_artifacts.append(
                    {
                        "system": system,
                        "case_id": case_id,
                        "path": _relative(destination),
                        "sha256": _sha256(destination),
                        "source_path": _relative(source),
                        "source_sha256": _sha256(source),
                    }
                )
            source_rule = source_root / "generated.rules"
            rule = source_rule.read_text(encoding="utf-8").strip()
            ir_status = materialize_posthoc_rule_ir(rule, destination_root)
            ir_name = (
                "generated.rule-ir.json"
                if ir_status["posthoc_rule_ir_ok"]
                else "generated.rule-ir-error.json"
            )
            frozen_ir = destination_root / ir_name
            frozen_artifacts.append(
                {
                    "system": system,
                    "case_id": case_id,
                    "path": _relative(frozen_ir),
                    "sha256": _sha256(frozen_ir),
                    "source_path": _relative(source_rule),
                    "source_sha256": _sha256(source_rule),
                    "derivation": "posthoc_rule_ir",
                }
            )

    summary = build_summary(results)
    write_summary(summary, output_root)
    source_files = [
        PROJECT_DIR / "semantic_generation.py",
        PROJECT_DIR / "benchmarks" / "benchmark.py",
        PROJECT_DIR / "benchmarks" / "summary.py",
    ]
    manifest = {
        "version": 1,
        "name": "suricataagent-semantic-intent-repair-v1",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "dataset_manifest": {
            "path": _relative(dataset_manifest),
            "sha256": _sha256(dataset_manifest),
        },
        "systems": list(EXPERIMENT_SYSTEMS),
        "case_count": len(case_ids),
        "result_count": len(results),
        "model": {
            "identifier": next(
                str(item["model"]) for item in results if item.get("model")
            ),
            "temperature": 0.1,
            "provider_base_url": os.getenv(
                "DEEPSEEK_BASE_URL", "https://api.wushuang233.com/v1"
            ),
        },
        "protocol": {
            "f_model_calls": 2,
            "g_paired_initial_system": "semantic_intent",
            "repair_feedback_samples": list(REPAIR_FEEDBACK_SAMPLES),
            "heldout_samples": list(REPAIR_HOLDOUT_SAMPLES),
            "diagnosis_before_each_repair": True,
            "best_visible_candidate_retained": True,
            "max_total_attempts": 3,
            "posthoc_rule_ir_does_not_control_generation": True,
        },
        "prompt_sha256": {
            "intent": _sha256_text(INTENT_SYSTEM_PROMPT),
            "intent_to_rule": _sha256_text(INTENT_RULE_SYSTEM_PROMPT),
            "repair_diagnosis": _sha256_text(REPAIR_DIAGNOSIS_SYSTEM_PROMPT),
            "diagnosis_to_rule": _sha256_text(DIAGNOSIS_REPAIR_SYSTEM_PROMPT),
        },
        "source_files": [
            {"path": _relative(path), "sha256": _sha256(path)} for path in source_files
        ],
        "source_results": source_results,
        "frozen_artifacts": frozen_artifacts,
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
    output_root = output_root.resolve()
    manifest = json.loads((output_root / "freeze-manifest.json").read_text("utf-8"))
    if _sha256(dataset_manifest) != manifest["dataset_manifest"]["sha256"]:
        raise ValueError("Benchmark v0 dataset changed after experiment freeze")
    for group in ("source_files", "source_results"):
        for item in manifest[group]:
            path = PROJECT_DIR / item["path"]
            if not path.is_file() or _sha256(path) != item["sha256"]:
                raise ValueError(f"frozen {group} item changed: {path}")
    for item in manifest["frozen_artifacts"]:
        frozen = PROJECT_DIR / item["path"]
        source = PROJECT_DIR / item["source_path"]
        if not frozen.is_file() or _sha256(frozen) != item["sha256"]:
            raise ValueError(f"frozen semantic artifact changed: {frozen}")
        if not source.is_file() or _sha256(source) != item["source_sha256"]:
            raise ValueError(f"source semantic artifact changed: {source}")
    for name, expected_hash in manifest["artifacts"].items():
        path = output_root / name
        if not path.is_file() or _sha256(path) != expected_hash:
            raise ValueError(f"frozen aggregate artifact changed: {path}")
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
