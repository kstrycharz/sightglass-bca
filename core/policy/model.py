"""Release-gate vocabulary.

Deliberately dependency-light: stdlib plus :mod:`core.vocab` only, for the same
reason the detection engine is (ADR-0011). The gate has to be evaluable in
places a database is not — a CI runner holding a downloaded JSON report, an
air-gapped release desk, a unit test — and an engine that can only run with a
live SQLAlchemy session is an engine nobody can verify.

The types here describe a *decision*, not a scan. Everything the gate reasons
about is a plain value that survives a round trip through JSON.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import date
from enum import StrEnum

from core.vocab import Severity


class GateDecision(StrEnum):
    """The three answers a release gate is allowed to give.

    ``INCONCLUSIVE`` is the one that matters and the one most tools omit. A
    scan whose unpacker hit its budget or whose analyzer OOMed did not look at
    the whole artifact, and reporting that as ``PASS`` tells a release manager
    something false. It is a distinct answer with a distinct exit code so a
    pipeline can choose its own posture rather than inheriting ours.
    """

    PASS = "pass"
    BLOCKED = "blocked"
    INCONCLUSIVE = "inconclusive"

    @property
    def exit_code(self) -> int:
        """Process exit code. 2 is reserved for tool error, which is not a
        decision and so has no member here."""
        return {
            GateDecision.PASS: 0,
            GateDecision.BLOCKED: 1,
            GateDecision.INCONCLUSIVE: 3,
        }[self]


class ViolationKind(StrEnum):
    """Why a finding blocks. Carried into the report so the failure message
    says which policy clause fired rather than just 'policy violation'."""

    SEVERITY_FLOOR = "severity_floor"
    BLOCKED_CATEGORY = "blocked_category"
    BLOCKED_RULE = "blocked_rule"
    BUDGET_EXCEEDED = "budget_exceeded"
    DEGRADED_SCAN = "degraded_scan"
    EXPIRED_WAIVER = "expired_waiver"


class BaselineMode(StrEnum):
    """``NEW_ONLY`` is the default, and the single most important knob in the
    product. See ADR-0016."""

    NEW_ONLY = "new_only"
    ALL = "all"


class DegradedPosture(StrEnum):
    FAIL = "fail"
    WARN = "warn"
    PASS = "pass"


@dataclass(frozen=True, slots=True)
class GateFinding:
    """A finding as the gate sees it.

    A narrow projection of the ORM row on purpose. The gate must not be able to
    read a plaintext secret, and it must not depend on the database, so it gets
    the deterministic fields it needs to make a decision and nothing else.
    """

    id: str
    rule_id: str
    category: str
    title: str
    severity: Severity
    status: str
    is_new: bool = True
    """False when this finding id was present in the baseline. Content-derived
    ids (ADR-0010) are what make this a set difference rather than a guess."""

    llm_dismissed: bool = False
    """The model called this a false positive. Tracked separately from
    ``status`` so the gate can decline to honour it (ADR-0017)."""

    artifact_path: str = ""
    value_masked: str = ""

    @property
    def is_open(self) -> bool:
        """Human dispositions close a finding; a model's does not, on its own.

        ``false_positive`` set by triage leaves ``llm_dismissed`` true, and the
        engine decides whether to honour it. Everything else here is a state a
        person put the finding into through the API, which the gate trusts.
        """
        return self.status not in ("false_positive", "accepted_risk", "fixed")


@dataclass(frozen=True, slots=True)
class Waiver:
    """A time-boxed exemption for one finding.

    Expiry is not optional. A waiver with no end date is a permanent hole in
    the gate that outlives the person who opened it and the reason they had.
    The loader rejects one without an expiry rather than defaulting it.
    """

    finding_id: str
    reason: str
    owner: str
    expires: date

    def is_expired(self, today: date) -> bool:
        return today > self.expires


@dataclass(frozen=True, slots=True)
class Violation:
    """One reason the gate failed. Rendered directly into CI output."""

    kind: ViolationKind
    detail: str
    finding_id: str = ""
    rule_id: str = ""
    severity: Severity | None = None
    title: str = ""
    artifact_path: str = ""

    def render(self) -> str:
        prefix = f"{self.severity.value.upper():8}" if self.severity else "SCAN    "
        where = f" [{self.artifact_path}]" if self.artifact_path else ""
        subject = self.title or self.detail
        return f"{prefix} {subject}{where}"


@dataclass(frozen=True, slots=True)
class WaivedFinding:
    finding_id: str
    title: str
    severity: Severity
    owner: str
    reason: str
    expires: date


@dataclass(frozen=True, slots=True)
class GateVerdict:
    """The full, serialisable answer.

    Carries what was *not* blocked as well as what was: a gate that reports
    only its failures gives a release manager no way to see that ten inherited
    criticals are still in the artifact, unfixed, just not new.
    """

    decision: GateDecision
    policy_name: str
    violations: tuple[Violation, ...] = ()
    waived: tuple[WaivedFinding, ...] = ()
    inherited: tuple[GateFinding, ...] = ()
    degraded_stages: tuple[str, ...] = ()
    counts_by_severity: dict[str, int] = field(default_factory=dict)
    new_counts_by_severity: dict[str, int] = field(default_factory=dict)
    total_findings: int = 0
    warnings: tuple[str, ...] = ()

    @property
    def exit_code(self) -> int:
        return self.decision.exit_code

    @property
    def blocked(self) -> bool:
        return self.decision is GateDecision.BLOCKED

    def summary_line(self) -> str:
        if self.decision is GateDecision.PASS:
            return (
                f"PASS — {self.total_findings} finding(s), "
                f"none blocking under {self.policy_name!r}"
            )
        if self.decision is GateDecision.INCONCLUSIVE:
            return (
                f"INCONCLUSIVE — scan incomplete "
                f"({len(self.degraded_stages)} degraded stage(s)) under '{self.policy_name}'"
            )
        return f"BLOCKED — {len(self.violations)} violation(s) under '{self.policy_name}'"
