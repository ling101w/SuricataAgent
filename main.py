"""Backward-compatible CLI bootstrap.

The historical B/C implementation lives in
``suricata_agent.legacy.detection_plan_pipeline``.  Existing scripts may still
execute ``python main.py`` or import its symbols while new application code uses
``production.py`` and the package facades.
"""

from __future__ import annotations

from suricata_agent.legacy import detection_plan_pipeline as _legacy

WorkflowConfig = _legacy.WorkflowConfig
build_workflow = _legacy.build_workflow
run_generation = _legacy.run_generation
main = _legacy.main


def __getattr__(name: str):
    return getattr(_legacy, name)


if __name__ == "__main__":
    raise SystemExit(main())
