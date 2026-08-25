"""The policy document: what blocks a release.

A policy is data, like a rule pack, and for the same reason — it belongs in the
release repository under review, not in the scanner's configuration. The team
that owns the artifact owns the definition of "shippable", and changing it
should require a pull request that somebody approves.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from core.policy.model import BaselineMode, DegradedPosture
from core.vocab import Severity

UNLIMITED = -1

# A waiver may not outlive a release cycle by much. Ninety days is long enough
# to schedule real remediation and short enough that it comes back for review
# while the person who granted it is still on the team.
DEFAULT_MAX_WAIVER_DAYS = 90


@dataclass(frozen=True, slots=True)
class Budgets:
    """Ceilings per severity for findings that do not hit the blocking floor.

    Exists so a policy can say "medium findings do not fail the build, but four
    hundred of them means something has gone wrong upstream". ``UNLIMITED``
    disables a ceiling rather than setting it to a large number.
    """

    critical: int = UNLIMITED
    high: int = UNLIMITED
    medium: int = UNLIMITED
    low: int = UNLIMITED
    info: int = UNLIMITED

    def limit_for(self, severity: Severity) -> int:
        return {
            Severity.CRITICAL: self.critical,
            Severity.HIGH: self.high,
            Severity.MEDIUM: self.medium,
            Severity.LOW: self.low,
            Severity.INFO: self.info,
        }[severity]


@dataclass(frozen=True, slots=True)
class Policy:
    """A complete gate configuration.

    The defaults are the shipping recommendation, not a placeholder: block on
    critical and high, compare against a baseline so only what this build
    introduced can fail it, fail closed on a degraded scan, and do not let the
    model's opinion unblock a release.
    """

    name: str = "default"
    version: int = 1

    block_at_or_above: Severity | None = Severity.HIGH
    """Findings at or above this severity block. ``None`` disables the floor,
    leaving only categories, rules, and budgets."""

    block_categories: frozenset[str] = frozenset()
    block_rules: frozenset[str] = frozenset()

    budgets: Budgets = field(default_factory=Budgets)
    baseline_mode: BaselineMode = BaselineMode.NEW_ONLY
    on_degraded: DegradedPosture = DegradedPosture.FAIL

    trust_llm_dismissals: bool = False
    """When false — the default — a finding the model called a false positive
    still blocks. See ADR-0017."""

    max_waiver_days: int = DEFAULT_MAX_WAIVER_DAYS
    require_waiver_owner: bool = True
    require_waiver_reason: bool = True

    def blocks(self, severity: Severity) -> bool:
        if self.block_at_or_above is None:
            return False
        return severity.rank <= self.block_at_or_above.rank
