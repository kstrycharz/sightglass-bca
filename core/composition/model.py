"""What a shipped artifact is made of.

The vocabulary for binary composition analysis: a component, where it was
found, and — the part most SBOM tooling gets wrong — *how confidently* it was
identified.

Dependency-light for the same reason the detection engine is (ADR-0011): this
runs inside the analyzer container, which installs one third-party package.

**Confidence is a first-class field.** A `package.json` that names
`@babel/parser@7.26.2` is a declaration; a version banner scraped out of a
stripped binary is an inference. An SBOM that presents both as the same kind of
fact is one its consumers learn to distrust, and CycloneDX has a field for the
distinction precisely because it matters downstream.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum


class Ecosystem(StrEnum):
    """Package ecosystems, named as the Package URL spec names them.

    The value is the PURL type, so `pkg:npm/...` falls out of the enum rather
    than a mapping that can drift from it.
    """

    NPM = "npm"
    NUGET = "nuget"
    PYPI = "pypi"
    GOLANG = "golang"
    CARGO = "cargo"
    MAVEN = "maven"
    GEM = "gem"
    GENERIC = "generic"


class Confidence(StrEnum):
    """How the component was identified.

    Ordered from strongest to weakest, and reported verbatim in the SBOM.
    """

    DECLARED = "declared"
    """A manifest the build itself shipped: package.json, .nuspec, Go build
    info. The artifact is telling you what it is."""

    EMBEDDED = "embedded"
    """Structured metadata inside a binary: PE version resources, .NET assembly
    attributes, ELF SONAME. Strong, but written by a build tool rather than a
    package manager."""

    INFERRED = "inferred"
    """A version banner or distinctive constant found in bytes — `zlib 1.3.1`
    in a statically-linked blob. Useful, and never to be presented as a
    declaration."""


# Characters that must be percent-encoded inside a purl's namespace, name or
# version. `@` is deliberately absent from the safe set: it separates the
# version, so a scoped npm namespace has to carry it encoded — the spec's own
# example is `pkg:npm/%40angular/animation@12.3.1`. `/` stays safe because a
# namespace legitimately contains it (`github.com/spf13`).
_PURL_UNSAFE = re.compile(r"[^A-Za-z0-9._~!$&'()*+,;=:/-]")


def _purl_quote(value: str) -> str:
    return _PURL_UNSAFE.sub(lambda m: f"%{ord(m.group()):02X}", value)


@dataclass(frozen=True, slots=True)
class Component:
    """One identified third-party component."""

    name: str
    version: str
    ecosystem: Ecosystem
    confidence: Confidence
    path_in_tree: str
    """Where in the unpack tree the evidence was found. A component without a
    location cannot be verified, argued with, or removed."""

    licence: str = ""
    """SPDX identifier where the manifest declared one. Named `licence` rather
    than `license` only to avoid shadowing nothing in particular; the wire
    format uses the SPDX spelling."""

    evidence: str = ""
    """The file or field that produced this. `package.json`, `Go buildinfo`,
    `PE VS_VERSIONINFO` — so a reader can go and check."""

    @property
    def purl(self) -> str:
        """Package URL. The join key for every advisory database."""
        namespace = ""
        name = self.name
        # npm scopes (`@babel/parser`) are a PURL namespace, not part of the
        # name — getting this wrong breaks every CVE lookup for scoped
        # packages, which on a modern Electron app is most of them.
        #
        # The leading `@` is KEPT and percent-encoded: the spec's own example
        # is `pkg:npm/%40angular/animation@12.3.1`. Stripping it yields a purl
        # that looks plausible and matches nothing.
        if self.ecosystem is Ecosystem.NPM and name.startswith("@") and "/" in name:
            namespace, _, name = name.partition("/")
        elif self.ecosystem is Ecosystem.GOLANG and "/" in name:
            namespace, _, name = name.rpartition("/")

        parts = f"pkg:{self.ecosystem.value}/"
        if namespace:
            parts += f"{_purl_quote(namespace)}/"
        parts += _purl_quote(name)
        if self.version:
            parts += f"@{_purl_quote(self.version)}"
        return parts

    @property
    def key(self) -> tuple[str, str, str]:
        """Identity for deduplication. The same library vendored into forty
        places is one component with forty locations, not forty components —
        the same reasoning as finding correlation."""
        return (self.ecosystem.value, self.name, self.version)


@dataclass(frozen=True, slots=True)
class ComponentInventory:
    """The bill of materials for one artifact."""

    components: tuple[Component, ...] = ()
    files_examined: int = 0
    truncated: bool = False
    """The walk stopped early. An inventory presented as complete when it is
    not is worse than no inventory."""

    def to_dict(self) -> dict[str, object]:
        return {
            "files_examined": self.files_examined,
            "truncated": self.truncated,
            "components": [
                {
                    "name": c.name,
                    "version": c.version,
                    "ecosystem": c.ecosystem.value,
                    "confidence": c.confidence.value,
                    "purl": c.purl,
                    "licence": c.licence,
                    "path_in_tree": c.path_in_tree,
                    "evidence": c.evidence,
                }
                for c in self.components
            ],
        }

    @property
    def by_ecosystem(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for component in self.components:
            counts[component.ecosystem.value] = counts.get(component.ecosystem.value, 0) + 1
        return counts
