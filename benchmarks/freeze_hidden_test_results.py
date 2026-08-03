"""Freeze, compare, and verify hidden-test-v1 primary A/E/G results."""

from __future__ import annotations

import argparse
import csv
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

from benchmarks.summary import build_summary, write_summary  # noqa: E402


DEFAULT_ROOT = PROJECT_DIR / "benchmarks" / "hidden-test-v1"
DEFAULT_OUTPUT = PROJECT_DIR / "benchmarks" / "experiments" / "hidden-test-v1-primary"
SYSTEMS = (
    "direct_llm",
    "direct_repair",
    "semantic_intent",
    "semantic_intent_repair",
)
PRIMARY_SYSTEMS = ("direct_llm", "direct_repair", "semantic_intent_repair")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    return path.resolve().relative_to(PROJECT_DIR).as_posix()


def _case_ids(root: Path) -> list[str]:
    manifest = json.loads((root / "manifest.public.json").read_text("utf-8"))
    ids = [str(item["case_id"]) for item in manifest.get("cases", [])]
    if manifest.get("split") != "test" or len(ids) != 30 or len(set(ids)) != 30:
        raise ValueError("hidden-test-v1 public manifest is not a 30-case test set")
    return ids


def _load_results(root: Path, case_ids: list[str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for system in SYSTEMS:
        for case_id in case_ids:
            path = root / "results" / system / case_id / "result.json"
            if not path.is_file():
                raise FileNotFoundError(f"missing hidden result: {path}")
            value = json.loads(path.read_text(encoding="utf-8"))
            if value.get("system") != system or value.get("case_id") != case_id:
                raise ValueError(f"hidden result identity mismatch: {path}")
            results.append(value)
    return results


def _system(summary: dict[str, Any], name: str) -> dict[str, Any]:
    return next(item for item in summary["systems"] if item["system"] == name)


def _pp(value: float | None) -> float | None:
    return round(value * 100, 3) if value is not None else None


def _delta(
    summary: dict[str, Any],
    source: str,
    target: str,
) -> dict[str, Any]:
    left = _system(summary, source)
    right = _system(summary, target)
    metrics = (
        "heldout_variant_recall",
        "heldout_false_positive_rate",
        "verified_rule_rate",
        "syntax_pass_rate",
        "original_detection_rate",
        "variant_recall",
        "false_positive_rate",
    )
    result: dict[str, Any] = {"source": source, "target": target}
    for name in metrics:
        before = left.get(name)
        after = right.get(name)
        result[name] = {
            "source_percent": _pp(before),
            "target_percent": _pp(after),
            "delta_percentage_points": (
                round((after - before) * 100, 3)
                if before is not None and after is not None
                else None
            ),
        }
    return result


def _check_pairing(results_root: Path, case_ids: list[str]) -> None:
    for case_id in case_ids:
        direct = results_root / "direct_llm" / case_id / "generated.rules"
        repaired_result = json.loads(
            (results_root / "direct_repair" / case_id / "result.json").read_text("utf-8")
        )
        semantic = results_root / "semantic_intent" / case_id / "generated.rules"
        semantic_repair_result = json.loads(
            (
                results_root
                / "semantic_intent_repair"
                / case_id
                / "result.json"
            ).read_text("utf-8")
        )
        if direct.is_file():
            if repaired_result["generation_metadata"].get(
                "paired_initial_rule_sha256"
            ) != _sha256_text_file(direct):
                raise ValueError(f"E is not paired with A for {case_id}")
        elif repaired_result.get("generation_ok"):
            raise ValueError(f"E generated without a deliverable A source for {case_id}")
        if semantic.is_file():
            if semantic_repair_result["generation_metadata"].get(
                "paired_initial_rule_sha256"
            ) != _sha256_text_file(semantic):
                raise ValueError(f"G is not paired with F for {case_id}")
        elif semantic_repair_result.get("generation_ok"):
            raise ValueError(f"G generated without a deliverable F source for {case_id}")
        for result in (repaired_result, semantic_repair_result):
            metadata = result["generation_metadata"]
            if not metadata.get("paired_source_system"):
                if result.get("generation_ok"):
                    raise ValueError(f"paired-source metadata is missing for {case_id}")
                continue
            if metadata.get("feedback_samples") != [
                "original",
                "positive-01",
                "negative-01",
            ]:
                raise ValueError(f"visible feedback contract changed for {case_id}")
            if metadata.get("holdout_samples") != ["positive-02", "negative-02"]:
                raise ValueError(f"holdout contract changed for {case_id}")


def _sha256_text_file(path: Path) -> str:
    text = path.read_text(encoding="utf-8").strip()
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _write_deltas(path: Path, primary: dict[str, Any]) -> dict[str, Any]:
    comparisons = [
        _delta(primary, "direct_llm", "direct_repair"),
        _delta(primary, "direct_repair", "semantic_intent_repair"),
        _delta(primary, "direct_llm", "semantic_intent_repair"),
    ]
    a_to_g = comparisons[-1]
    recall_delta = a_to_g["heldout_variant_recall"]["delta_percentage_points"]
    fp_delta = a_to_g["heldout_false_positive_rate"]["delta_percentage_points"]
    criterion = bool(
        recall_delta is not None
        and fp_delta is not None
        and recall_delta >= 10.0
        and fp_delta <= 5.0
    )
    value = {
        "version": 1,
        "comparisons": comparisons,
        "preregistered_threshold": {
            "recall_delta_minimum_percentage_points": 10.0,
            "false_positive_delta_maximum_percentage_points": 5.0,
        },
        "architecture_confirmation_threshold_passed": criterion,
    }
    path.write_text(
        json.dumps(value, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return value


def _write_primary_table(path: Path, primary: dict[str, Any]) -> None:
    fields = (
        "system",
        "case_total",
        "syntax_pass_rate",
        "original_detection_rate",
        "variant_recall",
        "heldout_variant_recall",
        "false_positive_rate",
        "heldout_false_positive_rate",
        "verified_rule_rate",
        "verified_cases",
        "avg_repair_attempts",
        "avg_latency_ms",
    )
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows(
            {field: item.get(field) for field in fields}
            for item in primary["systems"]
        )


def freeze(root: Path, output: Path) -> dict[str, Any]:
    root = root.resolve()
    output = output.resolve()
    freeze_path = output / "freeze-manifest.json"
    if freeze_path.exists():
        return verify(output)
    if output.exists():
        raise ValueError(f"refusing to overwrite partial hidden freeze: {output}")
    pre_run = root / "run-manifest.pre.json"
    if not pre_run.is_file():
        raise FileNotFoundError("hidden pre-run manifest is missing")

    case_ids = _case_ids(root)
    results = _load_results(root, case_ids)
    results_root = root / "results"
    _check_pairing(results_root, case_ids)
    output.mkdir(parents=True)
    shutil.copyfile(pre_run, output / "run-manifest.pre.json")
    for system in SYSTEMS:
        for case_id in case_ids:
            shutil.copytree(
                results_root / system / case_id,
                output / "results" / system / case_id,
            )

    full_summary = build_summary(results)
    all_systems_root = output / "all-systems"
    all_systems_root.mkdir()
    write_summary(full_summary, all_systems_root)
    primary_results = [
        item for item in results if item["system"] in PRIMARY_SYSTEMS
    ]
    primary = build_summary(primary_results)
    (output / "primary-summary.json").write_text(
        json.dumps(primary, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    _write_primary_table(output / "primary-summary.csv", primary)
    deltas = _write_deltas(output / "deltas.json", primary)

    frozen_files = [
        path
        for path in sorted(output.rglob("*"))
        if path.is_file() and path.name != "freeze-manifest.json"
    ]
    manifest = {
        "version": 1,
        "name": "suricataagent-hidden-test-v1-primary",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "case_count": len(case_ids),
        "result_count": len(results),
        "primary_result_count": len(primary_results),
        "systems": list(SYSTEMS),
        "primary_systems": list(PRIMARY_SYSTEMS),
        "architecture_confirmation_threshold_passed": deltas[
            "architecture_confirmation_threshold_passed"
        ],
        "files": [
            {
                "path": path.relative_to(output).as_posix(),
                "sha256": _sha256(path),
                "bytes": path.stat().st_size,
            }
            for path in frozen_files
        ],
    }
    freeze_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def verify(output: Path) -> dict[str, Any]:
    output = output.resolve()
    manifest = json.loads((output / "freeze-manifest.json").read_text("utf-8"))
    for item in manifest["files"]:
        path = output / item["path"]
        if not path.is_file() or path.stat().st_size != item["bytes"]:
            raise ValueError(f"frozen hidden artifact missing or resized: {path}")
        if _sha256(path) != item["sha256"]:
            raise ValueError(f"frozen hidden artifact changed: {path}")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    manifest = verify(args.output) if args.verify else freeze(args.root, args.output)
    print(
        json.dumps(
            {
                "experiment": str(args.output.resolve()),
                "case_count": manifest["case_count"],
                "result_count": manifest["result_count"],
                "threshold_passed": manifest[
                    "architecture_confirmation_threshold_passed"
                ],
                "verified": True,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
