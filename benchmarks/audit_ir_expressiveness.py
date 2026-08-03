"""Audit whether the current generation Detection Plan can represent Direct rules."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from collections import Counter
from pathlib import Path
from typing import Any


PROJECT_DIR = Path(__file__).resolve().parents[1]
if str(PROJECT_DIR) not in sys.path:
    sys.path.insert(0, str(PROJECT_DIR))

from rule_compiler import (  # noqa: E402
    DetectionFeature,
    DetectionSchemaError,
    RuleLintError,
    compile_candidate,
    parse_detection_data,
)
from rule_ir import RuleIR, RuleIRParseError, parse_suricata_rule  # noqa: E402
from rule_knowledge import CANDIDATE_ROLES  # noqa: E402


DEFAULT_BASELINE = PROJECT_DIR / "benchmarks" / "baselines" / "v0"
DEFAULT_OUTPUT_JSON = PROJECT_DIR / "benchmarks" / "ir-expressiveness-v0.json"

# These options are attached to a content match in Suricata but have no field in
# DetectionFeature. Dropping them changes detection semantics.
SEMANTIC_MATCH_OPTIONS = frozenset(
    {
        "startswith",
        "endswith",
        "distance",
        "within",
        "offset",
        "depth",
        "relative",
        "rawbytes",
        "bsize",
        "dsize",
        "isdataat",
        "byte_test",
        "byte_jump",
        "byte_extract",
        "flowbits",
        "transform",
    }
)
OPTIMIZER_ONLY_OPTIONS = frozenset({"fast_pattern"})


def _option_name(option: str) -> str:
    return option.split(":", 1)[0].strip().casefold()


def _candidate_payload(rule: RuleIR, role: str) -> dict[str, Any]:
    features: list[dict[str, Any]] = []
    for feature in rule.features:
        item: dict[str, Any] = {"buffer": feature.buffer}
        if feature.kind == "content":
            assert feature.content is not None
            item["content"] = feature.content.decode("utf-8")
            if feature.nocase:
                item["nocase"] = True
        else:
            item["pcre"] = feature.pcre
        features.append(item)
    return {
        "candidates": [
            {
                "role": role,
                "detection_scope": "case_specific",
                "direction": rule.direction,
                "protocol": rule.protocol,
                "method": rule.method,
                "features": features,
                "dynamic_fields": [],
                "reason": "Direct-rule expressiveness audit",
            }
        ],
        "semantic_testcases": [],
    }


def _structural_issues(rule: RuleIR) -> list[dict[str, str]]:
    issues: list[dict[str, str]] = []
    if rule.action != "alert":
        issues.append({"code": "ACTION_UNSUPPORTED", "detail": rule.action})
    if rule.protocol != "http":
        issues.append({"code": "PROTOCOL_UNSUPPORTED", "detail": rule.protocol})
    if rule.header.casefold() != "alert http any any -> any any":
        issues.append({"code": "HEADER_UNSUPPORTED", "detail": rule.header})
    expected_flow = {"established", "to_server"}
    if rule.direction == "response":
        expected_flow = {"established", "to_client"}
    if set(rule.flow) != expected_flow:
        issues.append(
            {
                "code": "FLOW_NOT_ROUNDTRIPPABLE",
                "detail": ",".join(rule.flow),
            }
        )
    for index, feature in enumerate(rule.features, start=1):
        if feature.negated:
            issues.append(
                {
                    "code": "NEGATED_MATCH_UNSUPPORTED",
                    "detail": f"feature {index}",
                }
            )
        if feature.kind == "content":
            assert feature.content is not None
            try:
                feature.content.decode("utf-8")
            except UnicodeDecodeError:
                issues.append(
                    {
                        "code": "BINARY_CONTENT_UNSUPPORTED",
                        "detail": f"feature {index}",
                    }
                )
    return issues


def audit_rule(case_id: str, rule_text: str, result: dict[str, Any]) -> dict[str, Any]:
    try:
        rule = parse_suricata_rule(rule_text)
    except RuleIRParseError as exc:
        return {
            "case_id": case_id,
            "direct_syntax_ok": bool(result.get("syntax_ok")),
            "direct_verified": bool(result.get("verified")),
            "post_generation_ir_parse_ok": False,
            "schema_accepted_roles": [],
            "compiler_accepted_roles": [],
            "semantic_loss_options": [],
            "optimizer_loss_options": [],
            "structural_issues": [
                {"code": "POST_GENERATION_IR_PARSE_ERROR", "detail": str(exc)}
            ],
            "schema_rejections": {},
            "compiler_rejections": {},
            "lossless_detection": False,
            "lossless_text": False,
            "status": "unsupported",
        }

    semantic_loss = sorted(
        {
            option
            for option in rule.other_options
            if _option_name(option) in SEMANTIC_MATCH_OPTIONS
        }
    )
    optimizer_loss = sorted(
        {
            option
            for option in rule.other_options
            if _option_name(option) in OPTIMIZER_ONLY_OPTIONS
        }
    )
    known_other = SEMANTIC_MATCH_OPTIONS | OPTIMIZER_ONLY_OPTIONS
    unknown_options = sorted(
        option for option in rule.other_options if _option_name(option) not in known_other
    )
    structural_issues = _structural_issues(rule)
    structural_issues.extend(
        {"code": "OPTION_UNSUPPORTED", "detail": option}
        for option in unknown_options
    )

    schema_accepted: list[str] = []
    compiler_accepted: list[str] = []
    schema_rejections: dict[str, str] = {}
    compiler_rejections: dict[str, str] = {}
    if not structural_issues:
        for role in CANDIDATE_ROLES:
            try:
                plan = parse_detection_data(_candidate_payload(rule, role))
                schema_accepted.append(role)
            except (DetectionSchemaError, UnicodeDecodeError) as exc:
                schema_rejections[role] = str(exc)
                continue
            try:
                compile_candidate(
                    plan.candidates[0],
                    sid=rule.sid,
                    candidate_index=1,
                    msg_prefix=case_id,
                )
                compiler_accepted.append(role)
            except (RuleLintError, ValueError) as exc:
                compiler_rejections[role] = str(exc)

    lossless_detection = bool(compiler_accepted) and not semantic_loss and not structural_issues
    lossless_text = lossless_detection and not optimizer_loss
    if not compiler_accepted or structural_issues:
        status = "unsupported"
    elif semantic_loss:
        status = "lossy"
    elif optimizer_loss:
        status = "optimizer_loss_only"
    else:
        status = "lossless"
    return {
        "case_id": case_id,
        "direct_syntax_ok": bool(result.get("syntax_ok")),
        "direct_verified": bool(result.get("verified")),
        "post_generation_ir_parse_ok": True,
        "feature_count": len(rule.features),
        "pcre_count": sum(feature.kind == "pcre" for feature in rule.features),
        "sticky_buffer_count": len({feature.buffer for feature in rule.features}),
        "sticky_buffers": sorted({feature.buffer for feature in rule.features}),
        "schema_accepted_roles": schema_accepted,
        "compiler_accepted_roles": compiler_accepted,
        "semantic_loss_options": semantic_loss,
        "optimizer_loss_options": optimizer_loss,
        "structural_issues": structural_issues,
        "schema_rejections": schema_rejections,
        "compiler_rejections": compiler_rejections,
        "lossless_detection": lossless_detection,
        "lossless_text": lossless_text,
        "status": status,
    }


def build_audit(baseline_root: Path = DEFAULT_BASELINE) -> dict[str, Any]:
    baseline_root = baseline_root.resolve()
    baseline = json.loads((baseline_root / "summary.json").read_text(encoding="utf-8"))
    direct_results = {
        item["case_id"]: item
        for item in baseline["cases"]
        if item.get("system") == "direct_llm"
    }
    cases: list[dict[str, Any]] = []
    for case_id in sorted(direct_results):
        rule_path = baseline_root / "direct-rules" / f"{case_id}.rules"
        cases.append(
            audit_rule(
                case_id,
                rule_path.read_text(encoding="utf-8").strip(),
                direct_results[case_id],
            )
        )
    counts = Counter(item["status"] for item in cases)
    summary = {
        "rule_total": len(cases),
        "post_generation_ir_parse_rate": round(
            sum(item["post_generation_ir_parse_ok"] for item in cases) / len(cases), 6
        ),
        "schema_accept_rate": round(
            sum(bool(item["schema_accepted_roles"]) for item in cases) / len(cases), 6
        ),
        "compiler_accept_rate": round(
            sum(bool(item["compiler_accepted_roles"]) for item in cases) / len(cases), 6
        ),
        "detection_lossless_rate": round(
            sum(item["lossless_detection"] for item in cases) / len(cases), 6
        ),
        "text_lossless_rate": round(
            sum(item["lossless_text"] for item in cases) / len(cases), 6
        ),
        "status_counts": dict(sorted(counts.items())),
    }
    return {
        "version": 1,
        "name": "benchmark-v0-direct-rule-generation-ir-expressiveness",
        "baseline": baseline_root.relative_to(PROJECT_DIR).as_posix(),
        "scope": "Current DetectionPlan/DetectionFeature generation schema and compiler",
        "summary": summary,
        "cases": cases,
    }


def write_audit(audit: dict[str, Any], output_json: Path) -> None:
    output_json = output_json.resolve()
    output_json.write_text(
        json.dumps(audit, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    output_csv = output_json.with_suffix(".csv")
    with output_csv.open("w", encoding="utf-8", newline="") as handle:
        fields = (
            "case_id",
            "direct_syntax_ok",
            "direct_verified",
            "post_generation_ir_parse_ok",
            "status",
            "lossless_detection",
            "lossless_text",
            "feature_count",
            "pcre_count",
            "sticky_buffer_count",
            "schema_accepted_roles",
            "compiler_accepted_roles",
            "semantic_loss_options",
            "optimizer_loss_options",
            "structural_issues",
        )
        writer = csv.DictWriter(handle, fieldnames=fields)
        writer.writeheader()
        for item in audit["cases"]:
            row = {field: item.get(field) for field in fields}
            for field in (
                "schema_accepted_roles",
                "compiler_accepted_roles",
                "semantic_loss_options",
                "optimizer_loss_options",
                "structural_issues",
            ):
                row[field] = json.dumps(row[field], ensure_ascii=False)
            writer.writerow(row)

    output_md = output_json.with_suffix(".md")
    summary = audit["summary"]
    lines = [
        "# Benchmark v0 IR expressiveness audit",
        "",
        "This audit compares the 12 frozen Direct LLM rules with the current generation-time ",
        "`DetectionPlan` / `DetectionFeature` schema and deterministic compiler.",
        "",
        f"- Post-generation Rule IR parse: {summary['post_generation_ir_parse_rate']:.1%}",
        f"- Generation schema accepts at least one role: {summary['schema_accept_rate']:.1%}",
        f"- Compiler accepts at least one role: {summary['compiler_accept_rate']:.1%}",
        f"- Detection-semantics lossless: {summary['detection_lossless_rate']:.1%}",
        f"- Text/optimizer lossless: {summary['text_lossless_rate']:.1%}",
        "",
        "| Case | Direct | IR status | Semantic options lost | Compiler roles |",
        "|---|---:|---|---|---|",
    ]
    for item in audit["cases"]:
        direct = "verified" if item["direct_verified"] else (
            "syntax" if item["direct_syntax_ok"] else "invalid"
        )
        lost = ", ".join(item["semantic_loss_options"]) or "-"
        roles = ", ".join(item["compiler_accepted_roles"]) or "-"
        lines.append(
            f"| {item['case_id']} | {direct} | {item['status']} | {lost} | {roles} |"
        )
    lines.extend(
        [
            "",
            "`optimizer_loss_only` means detection behavior can be reproduced but compiler output ",
            "drops an option such as `fast_pattern`. `lossy` means a match constraint such as ",
            "`startswith`, `distance`, or `within` is lost. `unsupported` means the schema/compiler ",
            "cannot emit the feature set at all under its current policy.",
            "",
        ]
    )
    output_md.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--baseline", type=Path, default=DEFAULT_BASELINE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT_JSON)
    args = parser.parse_args()
    audit = build_audit(args.baseline)
    write_audit(audit, args.output)
    print(json.dumps(audit["summary"], ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
