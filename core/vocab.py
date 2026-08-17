"""Shared vocabulary with no dependencies.

This module exists so the detection engine stays importable inside an analyzer
container without dragging in SQLAlchemy, Pydantic, or anything else. The
static analyzer image installs exactly one third-party package (PyYAML), which
keeps its attack surface small and its build fast — and, more importantly, the
scanner that runs in production is the same source the unit tests exercise
rather than a drifting reimplementation.

Anything imported by ``core.rules`` belongs here. Anything that needs a
database belongs in ``core.models``.
"""

from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        """Descending sort key. Explicit because report ordering must be
        deterministic, and alphabetical order is wrong."""
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]

    @property
    def blocks_release(self) -> bool:
        return self in (Severity.CRITICAL, Severity.HIGH)
