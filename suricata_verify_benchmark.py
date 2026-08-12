"""Backward-compatible shim for the suricata-verify smoke benchmark."""

from __future__ import annotations

from suricata_agent.benchmarks import suricata_verify as _benchmark


def __getattr__(name: str):
    return getattr(_benchmark, name)


__all__ = [name for name in dir(_benchmark) if not name.startswith("_")]
globals().update({name: getattr(_benchmark, name) for name in __all__})


if __name__ == "__main__":
    raise SystemExit(_benchmark.main())
