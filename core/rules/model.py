"""Rule definitions.

Rules are data, not code. A rule pack is a directory of YAML files with a
version and a hash, both recorded in the run manifest — which is what lets two
runs claim identical results (§2.5).

Deliberately over-inclusive by design: missing a live key is far worse than
surfacing a dud, so patterns favour recall and the correlator plus LLM triage
carry the precision burden. The precision/recall harness tracks the two
separately.
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass, field
from typing import Any

from core.vocab import Severity

# Byte-level scanning happens over decoded strings, so patterns are ordinary
# text regexes. Compiled once at load, never per candidate.
DEFAULT_FLAGS = re.MULTILINE


@dataclass(frozen=True, slots=True)
class Pattern:
    """One regex within a rule.

    ``capture`` names the group holding the secret itself. It matters: a rule
    matching ``password\\s*=\\s*(\\S+)`` must hash and mask the value, not the
    whole assignment, or the same secret written two ways would dedupe as two
    findings.
    """

    regex: re.Pattern[str]
    capture: str | int = 0
    source: str = ""

    def extract(self, match: re.Match[str]) -> str | None:
        try:
            value = match.group(self.capture)
        except LookupError:
            # A rule naming a capture group its regex does not define. Better a
            # skipped match than a crashed analyzer mid-scan.
            return None
        return value


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    name: str
    category: str
    severity: Severity
    patterns: tuple[Pattern, ...]

    confidence: float = 0.5
    cwe: str | None = None
    description: str = ""
    remediation: str = ""
    tags: tuple[str, ...] = ()

    min_entropy: float = 0.0
    """Shannon entropy floor for the captured value. Used by generic rules
    (``generic-high-entropy-assignment``) where the pattern alone matches far
    too much; specific rules with a strong shape leave it at zero."""

    min_length: int = 0
    max_length: int = 4096
    encodings: tuple[str, ...] = ("ascii", "utf-16le")

    requires_nearby: tuple[str, ...] = ()
    """Keywords that must appear within ``nearby_window`` characters of the
    match. This is what makes a shape-based rule specific rather than a
    high-entropy string detector: forty base64 characters are meaningless,
    forty base64 characters beside ``aws_secret_access_key`` are a credential."""

    nearby_window: int = 120

    shape_policy: str = "context"
    """How much of the structural filter to apply (``core.rules.shape``).

    ``context`` (default) rejects only on surroundings — blob slices and
    encoded structure. Safe for every rule anchored on a distinctive prefix.
    ``strict`` also rejects on the value's own shape, and belongs only to
    rules that match on shape alone. ``off`` disables the filter for rules
    whose match *is* structural, like the PEM header."""

    rejects_matching: tuple[re.Pattern[str], ...] = ()
    """Reject a captured value matching any of these.

    Nearly every "internal infrastructure" rule needs to say "…but not the
    public equivalent", and expressing that as a negative lookahead inside each
    pattern makes the pattern unreadable and has to be repeated per pattern.
    Found in the field: `scm-url` matched `git://github.com/dotnet/runtime` in
    a shipped .NET assembly, which is build metadata pointing at a public
    mirror, not disclosure of anyone's build server — and the rule already
    declared exactly that case as a negative test."""

    require_mixed_case: bool = False
    """Require upper + lower + digits. Vendor-issued secrets have this shape;
    a single-class run of the same length is almost always encoded data."""

    enabled: bool = True
    examples_positive: tuple[str, ...] = field(default=(), repr=False)
    examples_negative: tuple[str, ...] = field(default=(), repr=False)

    def accepts(self, value: str) -> bool:
        """Post-match gates that are cheaper to express here than in a regex."""
        if not (self.min_length <= len(value) <= self.max_length):
            return False
        if any(pattern.search(value) for pattern in self.rejects_matching):
            return False
        return not (self.min_entropy and shannon_entropy(value) < self.min_entropy)


def shannon_entropy(value: str) -> float:
    """Bits per character. The standard signal for "this looks like a key".

    Note it is length-independent, so a short random string scores as high as a
    long one — which is why rules pair it with ``min_length``.
    """
    if not value:
        return 0.0
    counts: dict[str, int] = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = len(value)
    return -sum((c / total) * math.log2(c / total) for c in counts.values())


@dataclass(frozen=True, slots=True)
class RulePack:
    version: str
    rules: tuple[Rule, ...]
    hash: str
    false_positives: frozenset[str] = frozenset()
    """Known-benign literal values: public test keys, RFC examples,
    ``AKIAIOSFODNN7EXAMPLE``, Windows SDK sample GUIDs. This corpus is the
    difference between a tool people use and a tool people mute."""

    def enabled_rules(self) -> tuple[Rule, ...]:
        # Sorted so scan order — and therefore evidence insertion order — never
        # depends on filesystem iteration order.
        return tuple(sorted((r for r in self.rules if r.enabled), key=lambda r: r.id))

    def is_known_false_positive(self, value: str) -> bool:
        return value.strip() in self.false_positives

    def to_manifest(self) -> dict[str, Any]:
        return {
            "rule_pack_version": self.version,
            "rule_pack_hash": self.hash,
            "rule_count": len(self.enabled_rules()),
        }
