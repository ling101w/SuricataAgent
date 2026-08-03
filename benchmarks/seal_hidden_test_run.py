"""Verify the freeze gate and write hidden-test-v1's immutable pre-run manifest."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from benchmarks.benchmark import (  # noqa: E402
    DIRECT_REPAIR_SYSTEM_PROMPT,
    DIRECT_SYSTEM_PROMPT,
    REPAIR_FEEDBACK_SAMPLES,
    REPAIR_HOLDOUT_SAMPLES,
)
from generate_tools import create_chat_model  # noqa: E402,F401
from semantic_generation import (  # noqa: E402
    DIAGNOSIS_REPAIR_SYSTEM_PROMPT,
    INTENT_RULE_SYSTEM_PROMPT,
    INTENT_SYSTEM_PROMPT,
    REPAIR_DIAGNOSIS_SYSTEM_PROMPT,
)
from validate_rules import check_suricata_runtime  # noqa: E402


DEFAULT_ROOT = PROJECT_DIR / "benchmarks" / "hidden-test-v1"
ARCHITECTURE_TAG = "semantic-intent-g-v1"
ARCHITECTURE_COMMIT = "4512c7599c1e2df088fdd9336d2b987de43d353d"


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _sha256_text(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=PROJECT_DIR,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()


def _relative(path: Path) -> str:
    return path.resolve().relative_to(PROJECT_DIR).as_posix()


def _verify_assets(root: Path) -> dict[str, Any]:
    manifest_path = root / "sealed-assets-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    if manifest.get("case_count") != 30 or manifest.get("pcap_count") != 150:
        raise ValueError("hidden-test-v1 asset counts are not frozen at 30/150")
    for item in manifest.get("assets", []):
        path = root / item["path"]
        if not path.is_file() or path.stat().st_size != item["bytes"]:
            raise ValueError(f"hidden asset is missing or resized: {path}")
        if _sha256(path) != item["sha256"]:
            raise ValueError(f"hidden asset hash mismatch: {path}")
    public_path = root / "manifest.public.json"
    runner_path = root / "manifest.runner.json"
    if _sha256(public_path) != manifest["public_manifest_sha256"]:
        raise ValueError("public hidden manifest hash mismatch")
    if _sha256(runner_path) != manifest["runner_manifest_sha256"]:
        raise ValueError("runner-view hidden manifest hash mismatch")
    return manifest


def seal(root: Path) -> dict[str, Any]:
    root = root.resolve()
    output = root / "run-manifest.pre.json"
    if output.exists():
        raise ValueError(f"pre-run manifest already exists: {output}")
    if (root / "results").exists():
        raise ValueError("hidden results already exist before freeze gate")
    if _git("status", "--porcelain"):
        raise ValueError("Git worktree must be clean before sealing hidden-test-v1")

    head = _git("rev-parse", "HEAD")
    tags = _git("tag", "--points-at", "HEAD").splitlines()
    architecture_target = _git("rev-list", "-n", "1", ARCHITECTURE_TAG)
    if architecture_target != ARCHITECTURE_COMMIT:
        raise ValueError("architecture tag no longer resolves to its frozen commit")
    if "hidden-test-v1-sealed" not in tags:
        raise ValueError("HEAD must carry the hidden-test-v1-sealed tag")

    assets = _verify_assets(root)
    runtime = check_suricata_runtime()
    if not runtime["ok"]:
        raise RuntimeError(str(runtime["message"]))
    executable = Path(str(runtime["suricata_bin"])).resolve()
    config = Path(str(runtime["config_path"])).resolve()
    version_process = subprocess.run(
        [str(executable), "-V"],
        cwd=executable.parent,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    version = (version_process.stdout + version_process.stderr).strip()

    source_files = [
        PROJECT_DIR / "benchmarks" / "benchmark.py",
        PROJECT_DIR / "benchmarks" / "summary.py",
        PROJECT_DIR / "semantic_generation.py",
        PROJECT_DIR / "validate_rules.py",
        PROJECT_DIR / "benchmarks" / "HIDDEN_TEST_PREREGISTRATION.md",
        PROJECT_DIR / "benchmarks" / "build_hidden_v1_cases.py",
    ]
    manifest = {
        "version": 1,
        "name": "suricataagent-hidden-test-v1-primary-pre-run",
        "sealed_at": datetime.now(timezone.utc).isoformat(),
        "architecture": {
            "tag": ARCHITECTURE_TAG,
            "commit": ARCHITECTURE_COMMIT,
        },
        "sealed_dataset_commit": head,
        "sealed_dataset_tag": "hidden-test-v1-sealed",
        "dataset": {
            "public_manifest": _relative(root / "manifest.public.json"),
            "public_manifest_sha256": assets["public_manifest_sha256"],
            "runner_manifest": _relative(root / "manifest.runner.json"),
            "runner_manifest_sha256": assets["runner_manifest_sha256"],
            "runner_manifest_derivation": (
                "Identical case list and paths; only top-level split/name permit the "
                "frozen dev-only runner loader to consume the sealed test set."
            ),
            "sealed_assets_manifest": _relative(
                root / "sealed-assets-manifest.json"
            ),
            "sealed_assets_manifest_sha256": _sha256(
                root / "sealed-assets-manifest.json"
            ),
            "case_count": 30,
            "pcap_count": 150,
        },
        "model": {
            "identifier": os.getenv("DEEPSEEK_MODEL", "gpt-5.5"),
            "provider_base_url": os.getenv(
                "DEEPSEEK_BASE_URL", "https://api.wushuang233.com/v1"
            ),
            "temperature": 0.1,
            "top_p": "provider_default",
            "seed": None,
            "api_timeout_seconds": 60,
            "api_max_retries": 2,
        },
        "systems": {
            "primary": ["direct_llm", "direct_repair", "semantic_intent_repair"],
            "paired_source_only": ["semantic_intent"],
            "max_total_attempts": 3,
            "repair_feedback_samples": list(REPAIR_FEEDBACK_SAMPLES),
            "heldout_samples": list(REPAIR_HOLDOUT_SAMPLES),
            "run_count": 1,
        },
        "decision_rule": {
            "recall_delta_minimum_percentage_points": 10.0,
            "false_positive_delta_maximum_percentage_points": 5.0,
            "comparison": "semantic_intent_repair minus direct_llm",
        },
        "prompt_sha256": {
            "direct": _sha256_text(DIRECT_SYSTEM_PROMPT),
            "direct_repair": _sha256_text(DIRECT_REPAIR_SYSTEM_PROMPT),
            "semantic_intent": _sha256_text(INTENT_SYSTEM_PROMPT),
            "semantic_intent_to_rule": _sha256_text(INTENT_RULE_SYSTEM_PROMPT),
            "repair_diagnosis": _sha256_text(REPAIR_DIAGNOSIS_SYSTEM_PROMPT),
            "diagnosis_to_rule": _sha256_text(DIAGNOSIS_REPAIR_SYSTEM_PROMPT),
        },
        "suricata": {
            "version": version,
            "executable": str(executable),
            "executable_sha256": _sha256(executable),
            "config": str(config),
            "config_sha256": _sha256(config),
        },
        "source_files": [
            {"path": _relative(path), "sha256": _sha256(path)}
            for path in source_files
        ],
        "commands": [
            "python -B benchmarks/benchmark.py --manifest benchmarks/hidden-test-v1/manifest.runner.json --results benchmarks/hidden-test-v1/results --all --mode direct_llm --resume",
            "python -B benchmarks/benchmark.py --manifest benchmarks/hidden-test-v1/manifest.runner.json --results benchmarks/hidden-test-v1/results --all --mode direct_repair --max-attempts 3 --resume",
            "python -B benchmarks/benchmark.py --manifest benchmarks/hidden-test-v1/manifest.runner.json --results benchmarks/hidden-test-v1/results --all --mode semantic_intent --resume",
            "python -B benchmarks/benchmark.py --manifest benchmarks/hidden-test-v1/manifest.runner.json --results benchmarks/hidden-test-v1/results --all --mode semantic_intent_repair --max-attempts 3 --resume",
        ],
    }
    output.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    args = parser.parse_args()
    manifest = seal(args.root)
    print(
        json.dumps(
            {
                "name": manifest["name"],
                "dataset_commit": manifest["sealed_dataset_commit"],
                "case_count": manifest["dataset"]["case_count"],
                "sealed": True,
            },
            ensure_ascii=False,
            indent=2,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
