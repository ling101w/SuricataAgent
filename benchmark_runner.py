"""Backward-compatible shim for :mod:`suricata_agent.benchmarks.runner`."""

from __future__ import annotations

from suricata_agent.benchmarks import runner as _runner


def __getattr__(name: str):
    return getattr(_runner, name)


__all__ = [name for name in dir(_runner) if not name.startswith("_")]
globals().update({name: getattr(_runner, name) for name in __all__})


if __name__ == "__main__":
    raise SystemExit(_runner.main())
