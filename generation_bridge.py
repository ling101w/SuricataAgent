"""Backward-compatible shim for the versioned generation bridge."""

from __future__ import annotations

from suricata_agent.integrations import generation_bridge as _bridge


def __getattr__(name: str):
    return getattr(_bridge, name)


__all__ = [name for name in dir(_bridge) if not name.startswith("_")]
globals().update({name: getattr(_bridge, name) for name in __all__})


if __name__ == "__main__":
    raise SystemExit(_bridge.main())
