"""Package facade for the Web API implementation.

The implementation stays at the repository root because its static files and
artifact defaults are rooted there. New imports should use this module.
"""

from __future__ import annotations

import web_app as _implementation

app = _implementation.app


def __getattr__(name: str):
    return getattr(_implementation, name)


__all__ = [name for name in dir(_implementation) if not name.startswith("_")]
