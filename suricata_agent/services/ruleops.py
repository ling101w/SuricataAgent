"""Persistent RuleOps knowledge base for verified final Suricata rules."""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
import threading
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Mapping, Sequence

from evidence_fingerprint import evidence_fingerprint_id, rule_logic_fingerprint_id
from coverage_graph import analyze_rule_coverage
from rule_ir import parse_suricata_rule, rule_ir_to_dict
from validate_rules import RulePolicy


SCHEMA_VERSION = 1
_LOCK = threading.RLock()


def _now() -> str:
    return datetime.now(UTC).isoformat()


def _sha256(value: str) -> str:
    return hashlib.sha256(value.strip().encode()).hexdigest()


def _empty_store() -> dict[str, Any]:
    return {
        "version": SCHEMA_VERSION,
        "updated_at": None,
        "records": [],
        "coverage_snapshots": {},
    }


def _record_case_ids(record: Mapping[str, Any]) -> list[str]:
    values = [record.get("case_id")]
    values.extend(record.get("case_ids", []))
    values.extend(
        item.get("case_id")
        for item in record.get("observations", [])
        if isinstance(item, Mapping)
    )
    return sorted({str(value) for value in values if value})


def _atomic_json(path: Path, value: Mapping[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = json.dumps(value, ensure_ascii=False, indent=2, default=str) + "\n"
    handle, temporary_name = tempfile.mkstemp(
        prefix=path.name + ".",
        suffix=".tmp",
        dir=str(path.parent),
        text=True,
    )
    try:
        with os.fdopen(handle, "w", encoding="utf-8") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary_name, path)
    finally:
        if os.path.exists(temporary_name):
            os.unlink(temporary_name)


class RuleOpsStore:
    """A small, deterministic JSON store suitable for local RuleOps workflows."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path).resolve()

    def _load(self) -> dict[str, Any]:
        if not self.path.is_file():
            return _empty_store()
        value = json.loads(self.path.read_text(encoding="utf-8"))
        if value.get("version") != SCHEMA_VERSION:
            raise ValueError("Rule KB schema version 不受支持")
        if not isinstance(value.get("records"), list):
            raise ValueError("Rule KB records 必须是数组")
        if not isinstance(value.get("coverage_snapshots", {}), dict):
            raise ValueError("Rule KB coverage_snapshots 必须是对象")
        return value

    def _save(self, value: dict[str, Any]) -> None:
        value["updated_at"] = _now()
        _atomic_json(self.path, value)

    def ingest(
        self,
        *,
        case_id: str,
        rule: str,
        rule_ir: Mapping[str, Any] | None,
        validation: Mapping[str, Any] | None,
        sample_matrix: Sequence[Mapping[str, object]],
        artifact_dir: str | Path,
    ) -> dict[str, Any]:
        if not validation or validation.get("passed") is not True:
            raise ValueError("Rule KB 只接受通过最终 Verify 的规则")
        parsed = parse_suricata_rule(rule)
        parsed_dict = rule_ir_to_dict(parsed)
        if rule_ir is not None and int(rule_ir.get("sid", -1)) != parsed.sid:
            raise ValueError("Rule IR 与 final rule SID 不一致")
        text_hash = _sha256(rule)
        evidence_hash = evidence_fingerprint_id(parsed)
        logic_hash = rule_logic_fingerprint_id(parsed)
        with _LOCK:
            store = self._load()
            exact = next(
                (item for item in store["records"] if item["rule_sha256"] == text_hash),
                None,
            )
            logic = next(
                (item for item in store["records"] if item["logic_fingerprint"] == logic_hash),
                None,
            )
            if exact is not None or logic is not None:
                existing = exact or logic
                assert existing is not None
                observations = existing.setdefault("observations", [])
                observation = {
                    "case_id": case_id,
                    "observed_at": _now(),
                    "artifact_dir": str(Path(artifact_dir).resolve()),
                }
                if observation not in observations:
                    observations.append(observation)
                existing["case_ids"] = sorted(
                    {*_record_case_ids(existing), case_id}
                )
                self._save(store)
                return {
                    "indexed": True,
                    "action": "deduplicated",
                    "duplicate_kind": "text" if exact is not None else "logic",
                    "record": self._public_record(existing),
                    "stats": self._stats(store),
                }

            record_id = "rule:" + text_hash[:16]
            sample_results = [] if validation is None else validation.get("sample_results", [])
            record = {
                "record_id": record_id,
                "case_id": case_id,
                "case_ids": [case_id],
                "sid": parsed.sid,
                "created_at": _now(),
                "status": "active",
                "rule": rule.strip(),
                "rule_sha256": text_hash,
                "evidence_fingerprint": evidence_hash,
                "logic_fingerprint": logic_hash,
                "ir": parsed_dict,
                "verification": {
                    "passed": bool(validation and validation.get("passed")),
                    "positive_coverage": None if validation is None else validation.get("positive_coverage"),
                    "false_positive_count": None if validation is None else validation.get("false_positive_count"),
                    "sample_count": len(sample_results) if isinstance(sample_results, list) else 0,
                },
                "sample_matrix": [dict(item) for item in sample_matrix],
                "artifact_dir": str(Path(artifact_dir).resolve()),
                "observations": [],
            }
            store["records"].append(record)
            store["records"].sort(key=lambda item: (item["case_id"], item["created_at"]))
            self._save(store)
            return {
                "indexed": True,
                "action": "created",
                "duplicate_kind": None,
                "record": self._public_record(record),
                "stats": self._stats(store),
            }

    def list_records(self, query: str | None = None) -> list[dict[str, Any]]:
        with _LOCK:
            records = self._load()["records"]
        needle = (query or "").strip().casefold()
        result = []
        for record in records:
            searchable = "\n".join(
                [
                    str(record.get("record_id", "")),
                    str(record.get("case_id", "")),
                    json.dumps(_record_case_ids(record), ensure_ascii=False),
                    str(record.get("sid", "")),
                    str(record.get("rule", "")),
                    json.dumps(record.get("ir", {}).get("evidence", {}), ensure_ascii=False),
                ]
            ).casefold()
            if needle and needle not in searchable:
                continue
            result.append(self._public_record(record))
        return list(reversed(result))

    def get_record(self, record_id: str) -> dict[str, Any] | None:
        with _LOCK:
            record = next(
                (item for item in self._load()["records"] if item["record_id"] == record_id),
                None,
            )
        return None if record is None else dict(record)

    def overview(self, query: str | None = None) -> dict[str, Any]:
        with _LOCK:
            store = self._load()
        records = self.list_records(query)
        return {
            "version": SCHEMA_VERSION,
            "updated_at": store.get("updated_at"),
            "stats": self._stats(store),
            "records": records,
            "duplicate_groups": self._duplicate_groups(store["records"]),
            "coverage_snapshots": store.get("coverage_snapshots", {}),
        }

    def rebuild_case_coverage(
        self,
        case_id: str,
        samples: Sequence[object],
        *,
        matrix_validator: Callable[..., Mapping[str, Any]],
        suricata_bin: str | None = None,
        config_path: str | None = None,
        syntax_timeout: int = 30,
        replay_timeout: int = 60,
    ) -> dict[str, Any]:
        """Jointly replay every active rule for one case before comparing coverage."""
        with _LOCK:
            store = self._load()
            records = [
                item
                for item in store["records"]
                if case_id in _record_case_ids(item) and item.get("status") == "active"
            ]
        if not records:
            raise ValueError(f"Rule KB 中没有 case {case_id} 的 active rule")
        if not samples:
            raise ValueError("Coverage Graph 需要完整 PCAP 样本矩阵")

        sid_map: dict[int, dict[str, Any]] = {}
        evaluation_rules: list[str] = []
        sid_base = 8_000_000
        for index, record in enumerate(records):
            evaluation_sid = sid_base + index
            source = str(record["rule"])
            remapped, count = re.subn(
                r"\bsid\s*:\s*\d+\s*;",
                f"sid:{evaluation_sid};",
                source,
                count=1,
                flags=re.IGNORECASE,
            )
            if count != 1:
                raise ValueError(f"规则 {record['record_id']} 无法重映射 SID")
            evaluation_rules.append(remapped)
            sid_map[evaluation_sid] = {
                "record_id": record["record_id"],
                "deployment_sid": record["sid"],
            }

        rules_text = "\n".join(evaluation_rules)
        validation = matrix_validator(
            rules_text,
            samples,
            policy=RulePolicy(
                sid_start=sid_base,
                require_contiguous_sids=True,
                positive_match_mode="any",
                max_rules=len(evaluation_rules),
            ),
            suricata_bin=suricata_bin,
            config_path=config_path,
            syntax_timeout=syntax_timeout,
            replay_timeout=replay_timeout,
        )
        if validation.get("syntax_ok") is not True:
            raise ValueError("Rule KB 联合规则集未通过 Suricata syntax gate")
        analysis = analyze_rule_coverage(
            rules_text,
            validation.get("sample_results", []),
            evaluated_sids=tuple(sid_map),
        )
        graph = analysis.public_dict()
        snapshot = {
            "case_id": case_id,
            "evidence": "joint_runtime_replay",
            "rule_count": len(records),
            "sample_count": len(samples),
            "evaluation_sid_map": {str(key): value for key, value in sid_map.items()},
            "recommended_record_ids": [
                sid_map[sid]["record_id"] for sid in analysis.recommended_sids
            ],
            "graph": graph,
            "validation_summary": {
                "passed": validation.get("passed"),
                "positive_coverage": validation.get("positive_coverage"),
                "false_positive_count": validation.get("false_positive_count"),
                "sample_results": validation.get("sample_results", []),
            },
        }
        self.save_coverage_snapshot(case_id, snapshot)
        return snapshot

    def save_coverage_snapshot(self, case_id: str, snapshot: Mapping[str, Any]) -> None:
        with _LOCK:
            store = self._load()
            store.setdefault("coverage_snapshots", {})[case_id] = {
                **dict(snapshot),
                "updated_at": _now(),
            }
            self._save(store)

    @staticmethod
    def _public_record(record: Mapping[str, Any]) -> dict[str, Any]:
        ir = record.get("ir", {})
        return {
            "record_id": record.get("record_id"),
            "case_id": record.get("case_id"),
            "case_ids": _record_case_ids(record),
            "sid": record.get("sid"),
            "created_at": record.get("created_at"),
            "status": record.get("status"),
            "rule_sha256": record.get("rule_sha256"),
            "evidence_fingerprint": record.get("evidence_fingerprint"),
            "logic_fingerprint": record.get("logic_fingerprint"),
            "direction": ir.get("direction"),
            "detection_scope": ir.get("detection_scope"),
            "evidence": ir.get("evidence", {}),
            "verification": record.get("verification", {}),
            "observation_count": len(record.get("observations", [])),
        }

    @staticmethod
    def _stats(store: Mapping[str, Any]) -> dict[str, int]:
        records = store.get("records", [])
        return {
            "rules": len(records),
            "cases": len(
                {case_id for item in records for case_id in _record_case_ids(item)}
            ),
            "verified": sum(bool(item.get("verification", {}).get("passed")) for item in records),
            "duplicate_observations": sum(len(item.get("observations", [])) for item in records),
            "coverage_snapshots": len(store.get("coverage_snapshots", {})),
        }

    @staticmethod
    def _duplicate_groups(records: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
        groups: dict[str, list[Mapping[str, Any]]] = {}
        for record in records:
            groups.setdefault(str(record.get("evidence_fingerprint")), []).append(record)
        return [
            {
                "evidence_fingerprint": fingerprint,
                "record_ids": [str(item.get("record_id")) for item in values],
                "case_ids": sorted(
                    {
                        case_id
                        for item in values
                        for case_id in _record_case_ids(item)
                    }
                ),
                "count": len(values),
            }
            for fingerprint, values in groups.items()
            if len(values) > 1
        ]


__all__ = ["RuleOpsStore", "SCHEMA_VERSION"]
