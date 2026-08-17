"""Evidence to findings.

Analyzers emit raw evidence; the correlator turns it into the deduplicated,
scored findings a human reads. Two properties matter more than anything else
here:

**Deduplication.** The same key baked into forty unpacked copies is one finding
with forty locations, not forty findings. A report that lists the same secret
forty times trains people to skim it.

**Determinism.** Evidence arrives from parallel analyzers in arbitrary order.
Everything is sorted before merging, and finding IDs are derived from content,
so the output is byte-identical across runs regardless of scheduling (§2.5).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

import structlog

from core.models import Evidence, Finding, FindingLocation, Suppression
from core.models.enums import DetectedBy, FindingStatus
from core.rules import Rule, RulePack

log = structlog.get_logger(__name__)

# Entropy above this is a meaningful signal that a value is key material rather
# than a word. Below it, a generic rule's match is probably a config string.
ENTROPY_STRONG = 4.5
ENTROPY_WEAK = 2.5


@dataclass(slots=True)
class CorrelationResult:
    findings: list[Finding] = field(default_factory=list)
    locations: list[FindingLocation] = field(default_factory=list)
    suppressed: int = 0

    @property
    def counts_by_severity(self) -> dict[str, int]:
        counts: dict[str, int] = defaultdict(int)
        for finding in self.findings:
            counts[finding.severity] += 1
        return dict(counts)


def correlate(
    run_id: str,
    evidence: list[Evidence],
    pack: RulePack,
    artifact_paths: dict[str, str],
    *,
    suppressions: list[Suppression] | None = None,
) -> CorrelationResult:
    """Group evidence into findings.

    ``artifact_paths`` maps artifact id to its path in the unpack tree, so a
    location can render ``setup.exe -> app.7z -> config/prod.json`` without the
    caller walking parent links per finding.
    """
    rules_by_id = {rule.id: rule for rule in pack.enabled_rules()}
    suppression_index = _index_suppressions(suppressions or [])

    # Group by (rule, value): the same secret under two different rules stays
    # two findings, because the remediation differs.
    groups: dict[tuple[str, str], list[Evidence]] = defaultdict(list)
    for item in sorted(evidence, key=_evidence_sort_key):
        groups[(item.rule_id, item.value_hash)].append(item)

    result = CorrelationResult()

    for (rule_id, value_hash), items in sorted(groups.items()):
        rule = rules_by_id.get(rule_id)
        if rule is None:
            # The rule pack changed between scan and correlation. Skipping is
            # correct: reporting a finding whose rule no longer exists would
            # leave the user with no description and no remediation.
            log.warning("correlator.unknown_rule", rule_id=rule_id, run_id=run_id)
            continue

        primary = items[0]
        anchor_path = artifact_paths.get(primary.artifact_id, "")

        if _is_suppressed(suppression_index, rule_id, value_hash, anchor_path):
            result.suppressed += 1
            continue

        finding_id = Finding.compute_id(rule_id, value_hash, anchor_path, primary.offset)
        confidence = _score(rule, items)

        result.findings.append(
            Finding(
                id=finding_id,
                run_id=run_id,
                rule_id=rule_id,
                category=rule.category,
                title=rule.name,
                severity=str(rule.severity),
                confidence=confidence,
                value_masked=primary.value_masked,
                value_hash=value_hash,
                entropy=primary.entropy,
                context_snippet=primary.context_snippet,
                cwe=rule.cwe,
                tags=list(rule.tags),
                remediation_md=rule.remediation,
                detected_by=DetectedBy.RULE,
                status=FindingStatus.OPEN,
            )
        )

        # Deduplicate locations: two rules matching at the same offset in the
        # same artifact is one place, not two.
        seen: set[tuple[str, int | None]] = set()
        for item in items:
            key = (item.artifact_id, item.offset)
            if key in seen:
                continue
            seen.add(key)
            result.locations.append(
                FindingLocation(
                    finding_id=finding_id,
                    run_id=run_id,
                    artifact_id=item.artifact_id,
                    path_in_tree=artifact_paths.get(item.artifact_id, ""),
                    offset=item.offset,
                    section=item.section,
                    encoding=item.encoding,
                )
            )

    result.findings.sort(key=lambda f: (_severity_rank(f.severity), f.rule_id, f.id))
    return result


def _evidence_sort_key(item: Evidence) -> tuple[str, str, str, int]:
    return (item.rule_id, item.value_hash, item.artifact_id, item.offset or 0)


def _severity_rank(severity: str) -> int:
    from core.vocab import Severity

    try:
        return Severity(severity).rank
    except ValueError:
        return 99


def _score(rule: Rule, items: list[Evidence]) -> float:
    """Confidence for a group of evidence.

    Starts at the rule's declared confidence and adjusts on signals the rule
    could not know at authoring time. Deliberately bounded and deterministic —
    no randomness, no model input. The LLM adjusts *status*, never this.
    """
    confidence = rule.confidence
    entropies = [e.entropy for e in items if e.entropy is not None]

    if entropies:
        peak = max(entropies)
        if peak >= ENTROPY_STRONG:
            confidence += 0.15
        elif peak <= ENTROPY_WEAK and rule.min_entropy == 0:
            # Low-entropy match on a rule that does not gate on entropy: often a
            # placeholder or a constant rather than a real credential.
            confidence -= 0.15

    if len(items) > 1:
        # The same value in several places is more likely to be a real embedded
        # credential than an incidental string match.
        confidence += 0.05

    if any(e.encoding == "utf-16le" for e in items):
        # Wide strings are Windows resource and config data, where real
        # credentials live — and where most scanners never look.
        confidence += 0.05

    return round(min(max(confidence, 0.05), 0.99), 3)


def _index_suppressions(suppressions: list[Suppression]) -> dict[tuple[str, str], list[str]]:
    index: dict[tuple[str, str], list[str]] = defaultdict(list)
    for suppression in suppressions:
        index[(suppression.rule_id, suppression.value_hash)].append(suppression.path_pattern)
    return index


def _is_suppressed(
    index: dict[tuple[str, str], list[str]],
    rule_id: str,
    value_hash: str,
    path: str,
) -> bool:
    from fnmatch import fnmatch

    patterns = index.get((rule_id, value_hash))
    if not patterns:
        return False
    return any(pattern == "*" or fnmatch(path, pattern) for pattern in patterns)
