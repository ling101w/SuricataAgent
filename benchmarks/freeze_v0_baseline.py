"""Freeze and verify the original A/B/C Benchmark v0 result set."""

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

from benchmarks.summary import build_summary, write_summary  # noqa: E402


DEFAULT_DATASET_MANIFEST = PROJECT_DIR / "benchmarks" / "v0-manifest.json"
DEFAULT_RESULTS = PROJECT_DIR / "benchmarks" / "results"
DEFAULT_BASELINE = PROJECT_DIR / "benchmarks" / "baselines" / "v0"
BASELINE_SYSTEMS = ("direct_llm", "compiler", "full_agent")


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _relative(path: Path) -> str:
    return path.resolve().relative_to(PROJECT_DIR).as_posix()


def _load_cases(dataset_manifest: Path) -> list[str]:
    value = json.loads(dataset_manifest.read_text(encoding="utf-8"))
    if value.get("version") != 1 or value.get("split") != "dev":
        raise ValueError("unsupported Benchmark v0 dataset manifest")
    case_ids = [str(item["case_id"]) for item in value.get("cases", [])]
    if len(case_ids) != 12 or len(set(case_ids)) != 12:
        raise ValueError("Benchmark v0 must contain exactly 12 unique cases")
    return case_ids


def _source_results(results_root: Path, case_ids: list[str]) -> list[dict[str, Any]]:
    results: list[dict[str, Any]] = []
    for system in BASELINE_SYSTEMS:
        for case_id in case_ids:
            path = results_root / system / case_id / "result.json"
            if not path.is_file():
                raise FileNotFoundError(f"missing baseline result: {path}")
            result = json.loads(path.read_text(encoding="utf-8"))
            if result.get("case_id") != case_id or result.get("system") != system:
                raise ValueError(f"baseline result identity mismatch: {path}")
            results.append(result)
    return results


def freeze_baseline(
    dataset_manifest: Path = DEFAULT_DATASET_MANIFEST,
    results_root: Path = DEFAULT_RESULTS,
    baseline_root: Path = DEFAULT_BASELINE,
) -> dict[str, Any]:
    dataset_manifest = dataset_manifest.resolve()
    results_root = results_root.resolve()
    baseline_root = baseline_root.resolve()
    freeze_path = baseline_root / "freeze-manifest.json"
    if freeze_path.exists():
        return verify_baseline(dataset_manifest, results_root, baseline_root)

    case_ids = _load_cases(dataset_manifest)
    results = _source_results(results_root, case_ids)
    baseline_root.mkdir(parents=True, exist_ok=False)
    direct_root = baseline_root / "direct-rules"
    direct_root.mkdir()

    source_files: list[dict[str, str]] = []
    direct_rules: list[dict[str, str]] = []
    for system in BASELINE_SYSTEMS:
        for case_id in case_ids:
            result_path = results_root / system / case_id / "result.json"
            source_files.append(
                {
                    "path": _relative(result_path),
                    "sha256": _sha256(result_path),
                }
            )
            if system != "direct_llm":
                continue
            source_rule = result_path.parent / "generated.rules"
            if not source_rule.is_file():
                raise FileNotFoundError(f"missing Direct rule: {source_rule}")
            frozen_rule = direct_root / f"{case_id}.rules"
            shutil.copyfile(source_rule, frozen_rule)
            direct_rules.append(
                {
                    "case_id": case_id,
                    "path": _relative(frozen_rule),
                    "sha256": _sha256(frozen_rule),
                    "source_path": _relative(source_rule),
                    "source_sha256": _sha256(source_rule),
                }
            )

    summary = build_summary(results)
    write_summary(summary, baseline_root)
    freeze_manifest = {
        "version": 1,
        "name": "suricataagent-benchmark-v0-abc-baseline",
        "frozen_at": datetime.now(timezone.utc).isoformat(),
        "dataset_manifest": {
            "path": _relative(dataset_manifest),
            "sha256": _sha256(dataset_manifest),
        },
        "systems": list(BASELINE_SYSTEMS),
        "case_count": len(case_ids),
        "result_count": len(results),
        "source_results": source_files,
        "direct_rules": direct_rules,
        "artifacts": {
            name: _sha256(baseline_root / name)
            for name in ("summary.json", "summary.csv", "results.csv")
        },
    }
    freeze_path.write_text(
        json.dumps(freeze_manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return freeze_manifest


def verify_baseline(
    dataset_manifest: Path = DEFAULT_DATASET_MANIFEST,
    results_root: Path = DEFAULT_RESULTS,
    baseline_root: Path = DEFAULT_BASELINE,
) -> dict[str, Any]:
    dataset_manifest = dataset_manifest.resolve()
    results_root = results_root.resolve()
    baseline_root = baseline_root.resolve()
    freeze_path = baseline_root / "freeze-manifest.json"
    if not freeze_path.is_file():
        raise FileNotFoundError(f"baseline is not frozen: {freeze_path}")
    frozen = json.loads(freeze_path.read_text(encoding="utf-8"))

    expected_dataset_hash = frozen["dataset_manifest"]["sha256"]
    if _sha256(dataset_manifest) != expected_dataset_hash:
        raise ValueError("Benchmark v0 dataset manifest changed after freeze")
    for item in frozen["source_results"]:
        path = PROJECT_DIR / item["path"]
        if not path.is_file() or _sha256(path) != item["sha256"]:
            raise ValueError(f"baseline source result changed: {path}")
    for item in frozen["direct_rules"]:
        frozen_rule = PROJECT_DIR / item["path"]
        source_rule = PROJECT_DIR / item["source_path"]
        if not frozen_rule.is_file() or _sha256(frozen_rule) != item["sha256"]:
            raise ValueError(f"frozen Direct rule changed: {frozen_rule}")
        if not source_rule.is_file() or _sha256(source_rule) != item["source_sha256"]:
            raise ValueError(f"source Direct rule changed: {source_rule}")
    for name, expected_hash in frozen["artifacts"].items():
        path = baseline_root / name
        if not path.is_file() or _sha256(path) != expected_hash:
            raise ValueError(f"frozen baseline artifact changed: {path}")
    return frozen


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dataset-manifest", type=Path, default=DEFAULT_DATASET_MANIFEST)
    parser.add_argument("--results", type=Path, default=DEFAULT_RESULTS)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--verify", action="store_true")
    args = parser.parse_args()
    operation = verify_baseline if args.verify else freeze_baseline
    result = operation(args.dataset_manifest, args.results, args.baseline)
    print(
        json.dumps(
            {
                "baseline": str(args.baseline.resolve()),
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
