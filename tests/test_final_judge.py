from __future__ import annotations

import json

import pytest

from final_judge import judge_passing_candidates


class _Model:
    def __init__(self, payload: dict[str, object]) -> None:
        self.payload = payload
        self.messages: list[object] = []

    def invoke(self, messages: list[object]) -> object:
        self.messages = messages
        return type(
            "Response",
            (),
            {"content": json.dumps(self.payload, ensure_ascii=False)},
        )()


def _candidate(index: int) -> dict[str, object]:
    return {
        "candidate_index": index,
        "role": "precision" if index == 1 else "robust",
        "detection_scope": "case_specific",
        "reason": "稳定攻击语义",
        "passed": True,
        "rule_ir": {"sid": 122 + index, "evidence": {"exploit": ["../"]}},
        "complexity": {"estimated_cost": 4 + index},
        "reference_metrics": {
            "positive_coverage": 1.0,
            "false_positive_count": 0,
            "decision_authority": "reference_only",
        },
        "validation": {
            "positive_coverage": 1.0,
            "false_positive_count": 0,
            "sample_results": [],
        },
    }


def test_final_judge_selects_only_from_passing_candidates() -> None:
    model = _Model(
        {
            "selected_candidate": 2,
            "reason": "保留 endpoint，同时较少绑定具体 payload",
            "overfitting_risks": ["需要更多真实正常流量"],
        }
    )

    result = judge_passing_candidates(
        base="路径遍历",
        poc="读取 passwd",
        request=b"GET /download?path=../../etc/passwd HTTP/1.1\r\n\r\n",
        response=b"",
        candidates=[_candidate(1), _candidate(2)],
        model=model,
    )

    assert result.selected_candidate == 2
    assert result.overfitting_risks == ("需要更多真实正常流量",)
    assert "decision_authority" in str(getattr(model.messages[-1], "content", ""))


def test_final_judge_rejects_candidate_outside_gate_pass_set() -> None:
    model = _Model(
        {
            "selected_candidate": 3,
            "reason": "越权选择",
            "overfitting_risks": [],
        }
    )

    with pytest.raises(ValueError, match="未通过确定性门禁"):
        judge_passing_candidates(
            base="路径遍历",
            poc="读取 passwd",
            request=b"GET / HTTP/1.1\r\n\r\n",
            response=b"",
            candidates=[_candidate(1), _candidate(2)],
            model=model,
        )


def test_final_judge_refuses_failed_candidate_in_input() -> None:
    failed = _candidate(2)
    failed["passed"] = False

    with pytest.raises(ValueError, match="未通过或非主规则"):
        judge_passing_candidates(
            base="路径遍历",
            poc="读取 passwd",
            request=b"GET / HTTP/1.1\r\n\r\n",
            response=b"",
            candidates=[_candidate(1), failed],
            model=_Model({}),
        )
