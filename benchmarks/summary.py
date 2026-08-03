"""Aggregate Benchmark v0 case results into stable ablation metrics."""

from __future__ import annotations

import argparse
import csv
import json
from collections import defaultdict
from pathlib import Path
from typing import Any


SYSTEM_ORDER = (
    "reference",
    "direct_llm",
    "compiler",
    "full_agent",
    "direct_validator",
    "direct_repair",
    "semantic_intent",
    "semantic_intent_repair",
)


def _ratio(numerator: int, denominator: int) -> float | None:
    return round(numerator / denominator, 6) if denominator else None


def _sample_result(item: dict[str, Any], name: str) -> dict[str, Any] | None:
    validation = item.get("validation")
    if not isinstance(validation, dict):
        return None
    for sample in validation.get("sample_results", []):
        if isinstance(sample, dict) and sample.get("name") == name:
            return sample
    return None


def build_summary(results: list[dict[str, Any]]) -> dict[str, Any]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in results:
        grouped[str(result["system"])].append(result)

    systems: list[dict[str, Any]] = []
    for system in SYSTEM_ORDER:
        items = grouped.get(system, [])
        if not items:
            continue
        case_total = len(items)
        syntax_passed = sum(bool(item.get("syntax_ok")) for item in items)
        original_total = sum(int(item.get("original_total", 0)) for item in items)
        original_hits = sum(int(item.get("original_hits", 0)) for item in items)
        variant_total = sum(int(item.get("variant_total", 0)) for item in items)
        variant_hits = sum(int(item.get("variant_hits", 0)) for item in items)
        negative_total = sum(int(item.get("negative_total", 0)) for item in items)
        negative_evaluated = sum(
            int(item.get("negative_evaluated", 0)) for item in items
        )
        false_positives = sum(int(item.get("false_positives", 0)) for item in items)
        verified = sum(bool(item.get("verified")) for item in items)
        repair_attempts = sum(int(item.get("repair_attempts", 0)) for item in items)
        latency_ms = sum(int(item.get("latency_ms", 0)) for item in items)
        heldout_variant_total = sum(int(item.get("variant_total", 0) >= 2) for item in items)
        heldout_variant_hits = sum(
            bool(sample and sample.get("passed"))
            for sample in (_sample_result(item, "positive-02") for item in items)
        )
        heldout_negative_results = [
            sample
            for sample in (_sample_result(item, "negative-02") for item in items)
            if sample is not None and sample.get("applicable", True)
        ]
        heldout_false_positives = sum(
            not bool(sample.get("passed")) for sample in heldout_negative_results
        )
        systems.append(
            {
                "system": system,
                "case_total": case_total,
                "syntax_pass_rate": _ratio(syntax_passed, case_total),
                "original_detection_rate": _ratio(original_hits, original_total),
                "variant_recall": _ratio(variant_hits, variant_total),
                "false_positive_rate": _ratio(false_positives, negative_evaluated),
                "verified_rule_rate": _ratio(verified, case_total),
                "verified_cases": verified,
                "negative_samples_unevaluated": negative_total - negative_evaluated,
                "heldout_variant_recall": _ratio(
                    heldout_variant_hits, heldout_variant_total
                ),
                "heldout_false_positive_rate": _ratio(
                    heldout_false_positives, len(heldout_negative_results)
                ),
                "heldout_negative_samples_unevaluated": (
                    case_total - len(heldout_negative_results)
                ),
                "avg_repair_attempts": (
                    round(repair_attempts / case_total, 3)
                    if system
                    in {"full_agent", "direct_repair", "semantic_intent_repair"}
                    else None
                ),
                "avg_latency_ms": round(latency_ms / case_total, 3),
            }
        )
    return {
        "version": 1,
        "metrics": {
            "syntax_pass_rate": "cases whose delivered rule loads in Suricata",
            "original_detection_rate": "original attack PCAPs that alert",
            "variant_recall": "equivalent attack variant PCAPs that alert",
            "false_positive_rate": "evaluated negative PCAPs that alert",
            "verified_rule_rate": "syntax + original + all variants + zero false positives",
            "avg_repair_attempts": "repair attempts after the initial generation",
            "heldout_variant_recall": "positive-02 recall; never exposed to repair systems",
            "heldout_false_positive_rate": "negative-02 false-positive rate; never exposed to repair systems",
        },
        "systems": systems,
        "cases": sorted(results, key=lambda item: (item["case_id"], item["system"])),
    }


def write_summary(summary: dict[str, Any], output_root: Path) -> None:
    (output_root / "summary.json").write_text(
        json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    with (output_root / "results.csv").open("w", encoding="utf-8", newline="") as handle:
        fields = (
            "case_id",
            "family",
            "system",
            "generation_ok",
            "syntax_ok",
            "original_hits",
            "original_total",
            "variant_hits",
            "variant_total",
            "false_positives",
            "negative_evaluated",
            "negative_total",
            "verified",
            "repair_attempts",
            "latency_ms",
            "failure_code",
        )
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: item.get(field) for field in fields} for item in summary["cases"])

    with (output_root / "summary.csv").open("w", encoding="utf-8", newline="") as handle:
        fields = (
            "system",
            "case_total",
            "syntax_pass_rate",
            "original_detection_rate",
            "variant_recall",
            "false_positive_rate",
            "verified_rule_rate",
            "verified_cases",
            "negative_samples_unevaluated",
            "heldout_variant_recall",
            "heldout_false_positive_rate",
            "heldout_negative_samples_unevaluated",
            "avg_repair_attempts",
            "avg_latency_ms",
        )
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        writer.writerows({field: item.get(field) for field in fields} for item in summary["systems"])


def load_results(output_root: Path) -> list[dict[str, Any]]:
    return [
        json.loads(path.read_text(encoding="utf-8"))
        for path in sorted(output_root.glob("*/*/result.json"))
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", type=Path, default=Path("benchmarks/results"))
    args = parser.parse_args()
    output_root = args.results.resolve()
    results = load_results(output_root)
    if not results:
        raise ValueError(f"No benchmark results found under {output_root}")
    summary = build_summary(results)
    write_summary(summary, output_root)
    print(json.dumps(summary["systems"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
