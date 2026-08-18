"""Reconnaissance — the inventory sweep, not a detector.

This module exists because of a gap that only became visible after a real
finding. Scanning a shipped vendor release, the rule pack reported nothing
interesting. The finding was there:

    svn+ssh://delinux03.de.moog.com/data/svn/nvce/tags/B99133-DV002-B-211b_11827

It was found by hand, with a throwaway script that swept the extracted tree
with deliberately over-broad patterns — every URI scheme, every UNC path,
every three-label hostname, every UPN — and grouped the results so a human
could read them. Nothing in the product did that, so the product could not
have found it.

**Recon is the inverse of detection.** A rule answers "is this specific bad
thing present?" and must be precise or it drowns the report. Recon answers
"what kinds of things are in here at all?" and must be over-inclusive or it
misses the thing nobody thought to write a rule for. They have opposite failure
modes, so they are deliberately separate code paths with separate output.

Recon output is an **inventory**, never a finding. It never appears in the
severity counts, never gates a release, and never carries a CWE. It is what a
human — or the rule-author model in ``core.llm.discovery`` — reads when asking
"what did we miss?".
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any

# Deliberately broad. Every pattern here would be a terrible detection rule and
# is a good reconnaissance probe. Ordered so the most structurally specific
# categories claim a string first.
SWEEPS: tuple[tuple[str, str, str], ...] = (
    (
        "uri_scheme",
        r"\b([a-z][a-z0-9+.\-]{1,14}://[^\s\"'<>&\x00]{3,180})",
        "Every URI, whatever the scheme. svn+ssh, git+ssh, ldap, mqtt, smb, "
        "and ftp all live here — the schemes nobody writes a rule for are "
        "exactly the ones that leak infrastructure.",
    ),
    (
        "unc_path",
        r"(\\\\[A-Za-z0-9._-]{2,60}\\[^\s\"<>|\x00]{0,120})",
        "UNC shares. Names a file server and often a build share.",
    ),
    (
        "windows_path",
        r"\b([A-Za-z]:\\[^\s\"<>|*?\x00\r\n]{4,160})",
        "Absolute Windows paths — build trees, user profiles, install roots.",
    ),
    (
        "posix_path",
        r"(/(?:home|Users|opt|srv|var|data|build|builds|workspace|mnt)/[^\s\"<>|:\x00]{3,160})",
        "Absolute POSIX paths under directories that imply a real machine.",
    ),
    (
        "email_or_upn",
        r"\b([A-Za-z0-9._%+-]{2,40}@[A-Za-z0-9.-]{3,50}\.[A-Za-z]{2,12})\b",
        "Addresses and user principal names. Distinguishes published contact "
        "addresses from individual employees.",
    ),
    # Before `hostname` on purpose: 10.20.30.40 is four dot-separated labels
    # and matches the hostname probe perfectly well. First category wins, so
    # the more specific shape has to be tested first.
    (
        "ip_address",
        r"\b((?:\d{1,3}\.){3}\d{1,3}(?::\d{1,5})?)\b",
        "IPv4 addresses, with port where present.",
    ),
    (
        "hostname",
        r"\b((?!\d+\.)[a-z0-9][a-z0-9-]{1,40}(?:\.[a-z0-9][a-z0-9-]{1,40}){2,}\.?[a-z]{0,12})\b",
        "Three-or-more-label hostnames. Public CDNs and internal servers look "
        "identical here on purpose — the point is to see all of them.",
    ),
    (
        "connection_string",
        r"([A-Za-z][A-Za-z0-9]{2,20}\s*=\s*[^;\s\"'\x00]{3,60}(?:;[A-Za-z][A-Za-z0-9]{2,20}\s*=\s*[^;\s\"'\x00]{1,60}){2,})",
        "Semicolon-delimited key=value strings — the shape of database and "
        "storage connection strings.",
    ),
    (
        "assignment",
        r"\b([A-Za-z_][A-Za-z0-9_.\-]{2,40}\s*[=:]\s*[^\s\"'<>;,\x00]{6,120})",
        "Any name=value pair. The broadest sweep, and where an unrecognised "
        "credential format shows up.",
    ),
    (
        "version_tag",
        r"\b([A-Z]{1,3}[0-9]{3,8}(?:[-_][A-Za-z0-9]{1,10}){1,5})\b",
        "Part numbers, build tags, and internal revision identifiers.",
    ),
)

_COMPILED: tuple[tuple[str, re.Pattern[str], str], ...] = tuple(
    (name, re.compile(pattern, re.IGNORECASE), why) for name, pattern, why in SWEEPS
)

# Values seen this many times across the tree are structural — a library
# constant, a boilerplate URL, a framework path. Interesting things in a
# shipped artifact are usually rare.
UBIQUITY_THRESHOLD = 40
MAX_PER_CATEGORY = 60
MAX_VALUE_CHARS = 200


@dataclass(slots=True)
class ReconCategory:
    name: str
    rationale: str
    total: int = 0
    distinct: int = 0
    samples: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "rationale": self.rationale,
            "total": self.total,
            "distinct": self.distinct,
            "samples": self.samples,
        }


@dataclass(slots=True)
class ReconInventory:
    """What kinds of things are in this artifact. Never a finding."""

    categories: list[ReconCategory] = field(default_factory=list)
    files_scanned: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "files_scanned": self.files_scanned,
            "categories": [c.to_dict() for c in self.categories],
        }

    def category(self, name: str) -> ReconCategory | None:
        return next((c for c in self.categories if c.name == name), None)


def sweep(
    strings: list[tuple[str, str, int, str]],
    *,
    max_per_category: int = MAX_PER_CATEGORY,
) -> ReconInventory:
    """Run every probe over extracted strings.

    ``strings`` is ``(value, relative_path, offset, encoding)``. A value is
    claimed by the first category that matches it, so the more structural
    categories take precedence and the broad ``assignment`` sweep collects the
    remainder rather than duplicating everything above it.

    Rarity is the ranking signal. In a 175-file installer the interesting
    string appears once; ``System.Runtime`` appears three thousand times.
    """
    counters: dict[str, Counter[str]] = {name: Counter() for name, _, _ in _COMPILED}
    locations: dict[str, dict[str, tuple[str, int, str]]] = {name: {} for name, _, _ in _COMPILED}
    files: set[str] = set()

    for value, path, offset, encoding in strings:
        files.add(path)
        for name, pattern, _ in _COMPILED:
            match = pattern.search(value)
            if match is None:
                continue
            found = match.group(1)[:MAX_VALUE_CHARS]
            counters[name][found] += 1
            locations[name].setdefault(found, (path, offset, encoding))
            break  # first category wins

    inventory = ReconInventory(files_scanned=len(files))

    for name, _, rationale in _COMPILED:
        counter = counters[name]
        if not counter:
            continue

        # Rare first, then alphabetically — deterministic, and it puts the
        # one-off internal hostname above the thousand-times-repeated library
        # constant, which is the whole point of the ordering.
        ranked = sorted(counter.items(), key=lambda kv: (kv[1], kv[0]))
        samples: list[dict[str, Any]] = []
        for found, occurrences in ranked:
            if occurrences > UBIQUITY_THRESHOLD:
                continue
            path, offset, encoding = locations[name][found]
            samples.append(
                {
                    "value": found,
                    "occurrences": occurrences,
                    "relative_path": path,
                    "offset": offset,
                    "encoding": encoding,
                }
            )
            if len(samples) >= max_per_category:
                break

        inventory.categories.append(
            ReconCategory(
                name=name,
                rationale=rationale,
                total=sum(counter.values()),
                distinct=len(counter),
                samples=samples,
            )
        )

    return inventory


def summarise(inventory: ReconInventory) -> str:
    lines = [f"{inventory.files_scanned} files swept"]
    for category in inventory.categories:
        lines.append(
            f"  {category.name:20} {category.distinct:>6} distinct "
            f"({category.total:>7} total), {len(category.samples)} sampled"
        )
    return "\n".join(lines)
