"""将历史规则转换为 Rule IR，并基于覆盖矩阵给出去重与包含分析。"""

from __future__ import annotations

import argparse
import json
import os
from collections import Counter
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from coverage_graph import CoverageAnalysis, analyze_rule_coverage
from detection_strategy import build_strategy_catalog
from rule_ir import RuleIR, parse_suricata_rules, serialize_rule_ir
from validate_rules import DEFAULT_RULE_POLICY, RulePolicy, validate_rule_matrix


def load_sample_results(path: str | Path) -> list[dict[str, object]]:
    """兼容 validation、validation-report 或裸 sample_results 数组。"""
    source = Path(path).resolve()
    value = json.loads(source.read_text(encoding="utf-8"))
    candidates: object = value
    evaluated_sids: object = None
    if isinstance(value, Mapping):
        evaluated_sids = value.get("expected_sids")
        if isinstance(value.get("sample_results"), list):
            candidates = value["sample_results"]
        elif isinstance(value.get("validation"), Mapping):
            validation = value["validation"]
            candidates = validation.get("sample_results")
            evaluated_sids = validation.get("expected_sids", evaluated_sids)
    if not isinstance(candidates, list):
        raise ValueError("输入不包含 sample_results 数组")
    if not candidates:
        raise ValueError("sample_results 不能为空，无法生成规则删除建议")
    results: list[dict[str, object]] = []
    for index, item in enumerate(candidates):
        if not isinstance(item, Mapping):
            raise ValueError(f"sample_results[{index}] 必须是对象")
        result = dict(item)
        # 旧版报告只在 validation 顶层记录规则集，把它下沉为逐样本覆盖契约。
        if "expected_any_sids" not in result and isinstance(evaluated_sids, list):
            result["expected_any_sids"] = list(evaluated_sids)
        results.append(result)
    return results


def load_traffic_matrix(
    path: str | Path,
    *,
    sample_root: str | Path | None = None,
) -> list[dict[str, object]]:
    """读取 traffic-matrix.json，并恢复每个样本的 PCAP 路径。"""
    source = Path(path).resolve()
    value = json.loads(source.read_text(encoding="utf-8"))
    if not isinstance(value, list) or not value:
        raise ValueError("traffic matrix 必须是非空数组")
    root = (
        Path(sample_root).resolve()
        if sample_root is not None
        else source.parent / "samples"
    )
    samples: list[dict[str, object]] = []
    for index, item in enumerate(value):
        if not isinstance(item, Mapping):
            raise ValueError(f"traffic matrix[{index}] 必须是对象")
        pcap_name = item.get("pcap_name")
        if not isinstance(pcap_name, str) or Path(pcap_name).name != pcap_name:
            raise ValueError(f"traffic matrix[{index}].pcap_name 无效")
        pcap_path = (root / pcap_name).resolve()
        if not pcap_path.is_file():
            raise ValueError(f"样本 PCAP 不存在：{pcap_path}")
        samples.append(
            {
                "name": str(item.get("name", f"sample-{index + 1}")),
                "expected": str(item.get("expected", "alert")),
                "reason": str(item.get("reason", "")),
                "pcap_path": pcap_path,
            }
        )
    return samples


def _summary(
    rules: Sequence[RuleIR],
    coverage: CoverageAnalysis | None,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "rule_count": len(rules),
        "sids": [rule.sid for rule in rules],
        "coverage_available": coverage is not None,
    }
    if coverage is None:
        result.update(
            {
                "recommended_rule_count": None,
                "recommended_sids": [],
                "relation_counts": {},
                "recommendation_counts": {},
                "warning": "未提供逐样本 matched_sids，仅生成 Rule IR，不给删除建议",
            }
        )
        return result

    result.update(
        {
            "recommended_rule_count": len(coverage.recommended_sids),
            "recommended_sids": list(coverage.recommended_sids),
            "relation_counts": dict(
                sorted(Counter(item.kind for item in coverage.relations).items())
            ),
            "recommendation_counts": dict(
                sorted(
                    Counter(
                        item.reason_code
                        for item in coverage.recommendations
                        if not item.keep
                    ).items()
                )
            ),
            "covered_positive_samples": list(coverage.covered_positive_samples),
            "uncovered_positive_samples": list(coverage.uncovered_positive_samples),
            "false_positive_samples": list(coverage.false_positive_samples),
            "optimization_method": coverage.optimization_method,
        }
    )
    return result


def analyze_rule_library(
    rules_text: str,
    sample_results: Sequence[object] | None = None,
    *,
    exact_limit: int = 16,
    evaluated_sids: Sequence[int] | None = None,
) -> tuple[tuple[RuleIR, ...], CoverageAnalysis | None, dict[str, Any]]:
    """解析规则库；仅在有覆盖证据时计算去重、包含与推荐集合。"""
    rules = parse_suricata_rules(rules_text)
    coverage = (
        analyze_rule_coverage(
            rules,
            sample_results,
            exact_limit=exact_limit,
            evaluated_sids=evaluated_sids,
        )
        if sample_results is not None
        else None
    )
    return rules, coverage, _summary(rules, coverage)


def _rule_library_policy(rules_text: str, rule_count: int) -> RulePolicy:
    """历史规则库已由用户显式选择，按实际 UTF-8 大小放宽生成链路限制。"""
    encoded_size = len(rules_text.encode("utf-8"))
    return RulePolicy(
        sid_start=None,
        require_contiguous_sids=False,
        positive_match_mode="any",
        max_rules=max(DEFAULT_RULE_POLICY.max_rules, rule_count),
        max_rule_bytes=max(DEFAULT_RULE_POLICY.max_rule_bytes, encoded_size),
    )


def write_rule_library_artifacts(
    output_dir: str | Path,
    rules: Sequence[RuleIR],
    coverage: CoverageAnalysis | None,
    summary: Mapping[str, Any],
) -> dict[str, str]:
    """写入稳定 JSON 产物；推荐规则保留原始文本。"""
    output = Path(output_dir).resolve()
    output.mkdir(parents=True, exist_ok=True)
    ir_path = output / "rule-ir.json"
    ir_path.write_text(serialize_rule_ir(tuple(rules)) + "\n", encoding="utf-8")
    summary_path = output / "library-summary.json"
    summary_path.write_text(
        json.dumps(dict(summary), ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )
    paths = {
        "rule_ir": str(ir_path),
        "summary": str(summary_path),
    }
    if coverage is not None:
        coverage_path = output / "coverage-graph.json"
        coverage_path.write_text(
            json.dumps(coverage.public_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        selected = set(coverage.recommended_sids)
        recommended_path = output / "recommended.rules"
        recommended_path.write_text(
            "\n".join(rule.raw_rule for rule in rules if rule.sid in selected) + "\n",
            encoding="utf-8",
        )
        paths["coverage_graph"] = str(coverage_path)
        paths["recommended_rules"] = str(recommended_path)
    return paths


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="分析 Suricata 历史规则库")
    parser.add_argument("rules", nargs="+", type=Path, help="一个或多个 .rules 文件")
    evidence = parser.add_mutually_exclusive_group()
    evidence.add_argument("--sample-results", type=Path, help="包含 matched_sids 的验证 JSON")
    evidence.add_argument("--traffic-matrix", type=Path, help="直接使用 PCAP 样本矩阵回放")
    parser.add_argument("--sample-root", type=Path, help="traffic matrix 中 PCAP 的目录")
    parser.add_argument("--output-dir", type=Path, default=Path("rule-library-analysis"))
    parser.add_argument("--exact-limit", type=int, default=16)
    parser.add_argument("--suricata-bin", default=os.getenv("SURICATA_BIN"))
    parser.add_argument("--suricata-config", default=os.getenv("SURICATA_CONFIG"))
    parser.add_argument("--syntax-timeout", type=int, default=60)
    parser.add_argument("--replay-timeout", type=int, default=60)
    parser.add_argument(
        "--summarize-strategies",
        action="store_true",
        help="让模型只对已证明的策略簇命名和归纳",
    )
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    rules_text = "\n".join(
        path.resolve().read_text(encoding="utf-8") for path in args.rules
    )
    samples: Sequence[object] | None = None
    validation: Mapping[str, Any] | None = None
    if args.sample_results is not None:
        samples = load_sample_results(args.sample_results)
    elif args.traffic_matrix is not None:
        parsed_rules = parse_suricata_rules(rules_text)
        traffic_samples = load_traffic_matrix(
            args.traffic_matrix,
            sample_root=args.sample_root,
        )
        validation = validate_rule_matrix(
            rules_text,
            traffic_samples,
            policy=_rule_library_policy(rules_text, len(parsed_rules)),
            suricata_bin=args.suricata_bin,
            config_path=args.suricata_config,
            syntax_timeout=args.syntax_timeout,
            replay_timeout=args.replay_timeout,
        )
        args.output_dir.mkdir(parents=True, exist_ok=True)
        (args.output_dir / "library-validation.json").write_text(
            json.dumps(validation, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        if validation.get("sample_results"):
            samples = validation["sample_results"]
    rules, coverage, summary = analyze_rule_library(
        rules_text,
        samples,
        exact_limit=args.exact_limit,
    )
    paths = write_rule_library_artifacts(
        args.output_dir,
        rules,
        coverage,
        summary,
    )
    if args.summarize_strategies and coverage is None:
        raise ValueError("--summarize-strategies 必须先提供 coverage 样本证据")
    if coverage is not None:
        model = None
        catalog_name = "strategy-clusters.json"
        if args.summarize_strategies:
            from generate_tools import create_chat_model

            model = create_chat_model()
            catalog_name = "detection-strategies.json"
        catalog = build_strategy_catalog(rules, coverage, model=model)
        catalog_path = args.output_dir.resolve() / catalog_name
        catalog_path.write_text(
            json.dumps(catalog, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        paths["strategy_catalog"] = str(catalog_path)
    if validation is not None:
        paths["validation"] = str(
            (args.output_dir / "library-validation.json").resolve()
        )
    print(
        json.dumps(
            {"summary": summary, "artifacts": paths},
            ensure_ascii=False,
            indent=2,
        )
    )
    if validation is not None and not validation.get("sample_results"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "analyze_rule_library",
    "load_sample_results",
    "load_traffic_matrix",
    "write_rule_library_artifacts",
]
