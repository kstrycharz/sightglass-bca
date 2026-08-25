"""The release gate.

Turns a set of findings into a ship / do-not-ship decision under a policy the
release repository owns. Deliberately importable without a database or a
model — see :mod:`core.policy.model` for why.
"""

from __future__ import annotations

from core.policy.engine import evaluate
from core.policy.loader import (
    POLICY_DIR,
    POLICY_FILE,
    WAIVERS_FILE,
    PolicyLoadError,
    discover_policy,
    load_policy,
    load_waivers,
    parse_policy,
    parse_waivers,
)
from core.policy.model import (
    BaselineMode,
    DegradedPosture,
    GateDecision,
    GateFinding,
    GateVerdict,
    Violation,
    ViolationKind,
    WaivedFinding,
    Waiver,
)
from core.policy.policy import UNLIMITED, Budgets, Policy
from core.policy.serde import verdict_from_dict, verdict_to_dict

__all__ = [
    "POLICY_DIR",
    "POLICY_FILE",
    "UNLIMITED",
    "WAIVERS_FILE",
    "BaselineMode",
    "Budgets",
    "DegradedPosture",
    "GateDecision",
    "GateFinding",
    "GateVerdict",
    "Policy",
    "PolicyLoadError",
    "Violation",
    "ViolationKind",
    "WaivedFinding",
    "Waiver",
    "discover_policy",
    "evaluate",
    "load_policy",
    "load_waivers",
    "parse_policy",
    "parse_waivers",
    "verdict_from_dict",
    "verdict_to_dict",
]
