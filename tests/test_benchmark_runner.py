from __future__ import annotations

from benchmark_runner import (
    DEFAULT_MANIFEST,
    aggregate_benchmark_results,
    load_benchmark_cases,
    mutation_contract_report,
    run_full_benchmark,
)
from traffic_cases import parse_http_request


def _complexity(cost: int) -> dict[str, int]:
    return {
        "estimated_cost": cost,
        "pcre_count": 1 if cost >= 8 else 0,
        "content_count": 2,
        "sticky_buffer_count": 1,
        "content_bytes": cost * 2,
    }


def _candidate(index: int, *, passed: bool, cost: int) -> dict[str, object]:
    return {
        "candidate_index": index,
        "detection_scope": (
            "success_indicator" if index == 3 else "case_specific"
        ),
        "passed": passed,
        "validation": {"passed": passed},
        "complexity": _complexity(cost),
    }


def test_benchmark_manifest_has_representative_categories_and_valid_http() -> None:
    cases = load_benchmark_cases(DEFAULT_MANIFEST)

    assert 10 <= len(cases) <= 20
    assert {
        "traversal",
        "command_injection",
        "sqli",
        "ssrf",
        "json_rce",
        "xml",
        "multipart",
    } <= {case.category for case in cases}
    for case in cases:
        parsed = parse_http_request(case.http_request)
        lengths = [
            value
            for name, value in parsed.headers
            if name.casefold() == "content-length"
        ]
        if parsed.body:
            assert lengths == [str(len(parsed.body))]
        else:
            assert lengths == []


def test_mutation_only_benchmark_builds_positive_and_negative_evidence() -> None:
    report = mutation_contract_report(load_benchmark_cases(DEFAULT_MANIFEST))

    assert report["mode"] == "mutation-only"
    assert report["case_count"] == 12
    assert report["positive_samples"] > report["case_count"]
    assert report["negative_samples"] >= report["case_count"]
    for case in report["cases"]:
        assert case["positive_samples"] >= 1
        assert case["negative_samples"] >= 1
        skip_codes = {item["code"] for item in case["mutation_skips"]}
        assert skip_codes <= {"RESPONSE_EVIDENCE_UNRECOGNIZED"}


def test_aggregate_benchmark_results_reports_requested_regression_metrics() -> None:
    runs = [
        {
            "case_id": "case-a",
            "category": "traversal",
            "state": {
                "status": "passed",
                "attempt": 1,
                "selected_candidate": 1,
                "validation_result": {
                    "sample_results": [
                        {"name": "p1", "expected": "alert", "passed": True},
                        {
                            "name": "response-only",
                            "expected": "alert",
                            "passed": True,
                            "applicable": False,
                        },
                        {"name": "n1", "expected": "no_alert", "passed": True},
                    ]
                },
                "attempts": [
                    {
                        "candidates": [
                            _candidate(1, passed=True, cost=4),
                            _candidate(2, passed=True, cost=5),
                            _candidate(3, passed=False, cost=6),
                        ]
                    }
                ],
            },
        },
        {
            "case_id": "case-b",
            "category": "json_rce",
            "state": {
                "status": "failed",
                "attempt": 2,
                "selected_candidate": 2,
                "failure_code": "NEGATIVE_FALSE_POSITIVE",
                "validation_result": {
                    "sample_results": [
                        {"name": "p2", "expected": "alert", "passed": False},
                        {"name": "n2", "expected": "no_alert", "passed": False},
                    ]
                },
                "attempts": [
                    {
                        "candidates": [
                            _candidate(1, passed=False, cost=5),
                            _candidate(2, passed=False, cost=6),
                            _candidate(3, passed=False, cost=7),
                        ]
                    },
                    {
                        "candidates": [
                            _candidate(1, passed=False, cost=7),
                            _candidate(2, passed=True, cost=8),
                            _candidate(3, passed=False, cost=9),
                        ]
                    },
                ],
            },
        },
    ]

    report = aggregate_benchmark_results(runs)

    assert report["case_pass_rate"] == 0.5
    assert report["positive_recall"] == 0.5
    assert report["negative_fp_rate"] == 0.5
    assert report["candidate_pass_rate"] == 0.333333
    assert report["primary_candidate_pass_rate"] == 0.5
    assert report["supplemental_candidate_pass_rate"] == 0.0
    assert report["retry_count"] == 1
    assert report["average_retry_count"] == 0.5
    assert report["rule_complexity"]["estimated_cost"] == 6.0
    assert report["rule_complexity"]["pcre_count"] == 0.5


def test_failed_generation_and_lint_rejection_are_not_dropped_from_metrics() -> None:
    report = aggregate_benchmark_results(
        [
            {
                "case_id": "failed",
                "category": "sqli",
                "state": {
                    "status": "failed",
                    "attempt": 1,
                    "sample_matrix": [
                        {"name": "p", "expected": "alert"},
                        {"name": "n", "expected": "no_alert"},
                    ],
                    "validation_result": None,
                    "attempts": [
                        {
                            "candidates": [
                                {
                                    "candidate_index": index,
                                    "passed": False,
                                    "compile_error": "lint rejected",
                                    "validation": None,
                                }
                                for index in range(1, 4)
                            ]
                        }
                    ],
                },
            }
        ]
    )

    assert report["positive_recall"] == 0.0
    assert report["candidate_pass_rate"] == 0.0
    assert report["candidates_evaluated"] == 3
    assert report["negative_samples"] == 0
    assert report["negative_samples_unevaluated"] == 1


def test_runner_error_uses_manifest_sample_counts_in_recall_denominator() -> None:
    report = aggregate_benchmark_results(
        [
            {
                "case_id": "passed",
                "category": "traversal",
                "expected_samples": {"positive": 1, "negative": 1},
                "state": {
                    "status": "passed",
                    "attempt": 1,
                    "validation_result": {
                        "sample_results": [
                            {"name": "p1", "expected": "alert", "passed": True},
                            {"name": "n1", "expected": "no_alert", "passed": True},
                        ]
                    },
                    "attempts": [],
                },
            },
            {
                "case_id": "runner-error",
                "category": "sqli",
                "expected_samples": {"positive": 3, "negative": 2},
                "state": {
                    "status": "failed",
                    "attempt": 0,
                    "failure_code": "BENCHMARK_RUN_ERROR",
                    "validation_result": None,
                    "attempts": [],
                },
            },
        ]
    )

    assert report["positive_samples"] == 4
    assert report["positive_recall"] == 0.25
    assert report["negative_samples"] == 1
    assert report["negative_samples_unevaluated"] == 2


def test_model_preflight_failure_still_writes_complete_benchmark_metrics(
    tmp_path,
    monkeypatch,
) -> None:
    cases = load_benchmark_cases(DEFAULT_MANIFEST)[:2]
    monkeypatch.setattr(
        "benchmark_runner.create_chat_model",
        lambda: (_ for _ in ()).throw(RuntimeError("model unavailable")),
    )

    report = run_full_benchmark(
        cases,
        tmp_path,
        runner=lambda **_kwargs: (_ for _ in ()).throw(
            AssertionError("模型预检失败时不应运行 case")
        ),
    )

    assert report["case_count"] == 2
    assert report["case_pass_rate"] == 0.0
    assert report["positive_recall"] == 0.0
    assert report["positive_samples"] > 0
    assert report["negative_samples_unevaluated"] > 0
    assert all(
        item["failure_code"] == "BENCHMARK_MODEL_ERROR"
        for item in report["cases"]
    )
