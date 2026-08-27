"""Analyzer image naming.

The tag used to be hard-coded in eight places. What matters now is that the one
configuration point behaves, and — more importantly — that leaving it unset is
indistinguishable from the old hard-coded behaviour, because every existing
workflow depends on that.
"""

from __future__ import annotations

import pytest

from core.sandbox.images import ANALYZERS, DEFAULT_TAG, analyzer_image, analyzer_tag


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Start from no configuration, whatever the developer's shell exports."""
    monkeypatch.delenv("SIGHTGLASS_ANALYZER_TAG", raising=False)
    for name in ANALYZERS:
        monkeypatch.delenv(f"SIGHTGLASS_{name.upper()}_IMAGE", raising=False)


class TestBackwardCompatibility:
    """Unset must be identical to the behaviour this replaced."""

    def test_the_default_is_exactly_what_was_hard_coded(self) -> None:
        assert analyzer_image("hello") == "sightglass/hello:dev"
        assert analyzer_image("static") == "sightglass/static:dev"
        assert analyzer_image("unpack") == "sightglass/unpack:dev"

    def test_an_exported_but_empty_tag_falls_back(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The usual shape of a broken deployment script. Honouring it would
        produce `sightglass/static:` and a daemon error that says nothing about
        the cause."""
        monkeypatch.setenv("SIGHTGLASS_ANALYZER_TAG", "   ")
        assert analyzer_image("static") == "sightglass/static:dev"

    def test_the_default_constant_matches_the_documented_one(self) -> None:
        assert DEFAULT_TAG == "dev"
        assert analyzer_tag() == "dev"


class TestTheTagIsConfigurable:
    @pytest.mark.parametrize("tag", ["latest", "0.1.0", "a3f9c21", "v2.0.0-rc1"])
    def test_every_analyzer_picks_up_the_tag(
        self, tag: str, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SIGHTGLASS_ANALYZER_TAG", tag)
        for name in ANALYZERS:
            assert analyzer_image(name) == f"sightglass/{name}:{tag}"

    def test_surrounding_whitespace_is_ignored(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """`export SIGHTGLASS_ANALYZER_TAG="0.1.0 "` is a typo, not a tag."""
        monkeypatch.setenv("SIGHTGLASS_ANALYZER_TAG", "  0.1.0  ")
        assert analyzer_image("static") == "sightglass/static:0.1.0"

    def test_it_is_read_at_call_time_not_at_import(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The constants this replaced were evaluated once when the module
        loaded, so a worker that set the variable after start-up could not
        change them."""
        monkeypatch.setenv("SIGHTGLASS_ANALYZER_TAG", "first")
        assert analyzer_image("static") == "sightglass/static:first"
        monkeypatch.setenv("SIGHTGLASS_ANALYZER_TAG", "second")
        assert analyzer_image("static") == "sightglass/static:second"


class TestPerAnalyzerOverride:
    """`SIGHTGLASS_<NAME>_IMAGE` predates the tag setting and must keep
    working; it is also the only way to pin a digest or move one analyzer to a
    different registry."""

    def test_a_full_reference_wins_over_the_tag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SIGHTGLASS_ANALYZER_TAG", "0.1.0")
        monkeypatch.setenv(
            "SIGHTGLASS_STATIC_IMAGE", "registry.internal/sightglass/static@sha256:abc123"
        )
        assert analyzer_image("static") == "registry.internal/sightglass/static@sha256:abc123"
        # and only that one analyzer is affected
        assert analyzer_image("unpack") == "sightglass/unpack:0.1.0"

    def test_an_empty_override_does_not_shadow_the_tag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SIGHTGLASS_ANALYZER_TAG", "0.1.0")
        monkeypatch.setenv("SIGHTGLASS_STATIC_IMAGE", "")
        assert analyzer_image("static") == "sightglass/static:0.1.0"


class TestTheBuildAndTheRunAgree:
    """A tag the Makefile builds but the orchestrator does not run is a scan
    that fails with 'image not found' at the worst possible moment."""

    def test_every_analyzer_the_makefile_builds_is_named_here(self) -> None:
        from pathlib import Path

        makefile = Path("Makefile").read_text(encoding="utf-8")
        for name in ANALYZERS:
            assert f"image-{name}:" in makefile, f"Makefile has no image-{name} target"
            assert f"sightglass/{name}:$(SIGHTGLASS_ANALYZER_TAG)" in makefile

    def test_the_powershell_twin_builds_the_same_set(self) -> None:
        """`./make.ps1 <target>` is documented as mirroring every Makefile
        target, so the two cannot disagree about which images exist."""
        from pathlib import Path

        script = Path("make.ps1").read_text(encoding="utf-8")
        for name in ANALYZERS:
            assert f"'image-{name}'" in script
            assert f'sightglass/{name}:$(Get-AnalyzerTag)' in script
