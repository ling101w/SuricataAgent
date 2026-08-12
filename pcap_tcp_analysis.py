"""Backward-compatible shim for packaged capture analysis."""

from __future__ import annotations

from suricata_agent.traffic import analysis as _implementation


def __getattr__(name: str):
    return getattr(_implementation, name)


__all__ = [name for name in dir(_implementation) if not name.startswith("_")]
globals().update({name: getattr(_implementation, name) for name in __all__})
