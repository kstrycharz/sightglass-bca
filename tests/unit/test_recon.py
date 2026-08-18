"""Reconnaissance sweeps.

The regression test for a gap that cost a real finding. A shipped vendor
release contained an internal Subversion URL four levels deep; the rule pack
reported nothing, because no rule described it and nothing in the product
inventoried what was actually there.

Recon is deliberately over-inclusive — every pattern here would be a terrible
detection rule. The tests assert that breadth, and assert that the ranking puts
the rare string above the ubiquitous one, because that ordering is what makes
the output readable by a human or a model.
"""

from __future__ import annotations

from core.rules.recon import UBIQUITY_THRESHOLD, ReconInventory, summarise, sweep

# The string that motivated the module, in its original context.
SVN_STRING = (
    'def="svn+ssh://delinux03.de.moog.com/data/svn/nvce/tags/'
    'B99133-DV002-B-211b_11827" dsc="FirmwareSourceCodeTag"'
)
PROFILE_STRING = r"IconFile=C:\Users\shoepfer\AppData\Local\Mozilla\Firefox\Profiles\8p7ab414\a.ico"


def strings(*values: str) -> list[tuple[str, str, int, str]]:
    return [(v, f"file{i}.bin", i * 16, "ascii") for i, v in enumerate(values)]


class TestFindsWhatRulesMissed:
    """The headline case: recon surfaces it with no rule for it at all."""

    def test_svn_ssh_url_is_inventoried(self) -> None:
        inventory = sweep(strings(SVN_STRING))
        uris = inventory.category("uri_scheme")

        assert uris is not None
        assert any("svn+ssh://delinux03.de.moog.com" in s["value"] for s in uris.samples)

    def test_developer_profile_path_is_inventoried(self) -> None:
        inventory = sweep(strings(PROFILE_STRING))
        paths = inventory.category("windows_path")

        assert paths is not None
        assert any("shoepfer" in s["value"] for s in paths.samples)

    def test_sweeps_cover_the_shapes_that_leak(self) -> None:
        inventory = sweep(
            strings(
                SVN_STRING,
                PROFILE_STRING,
                r"\\buildshare01\releases\firmware",
                "/home/jenkins/workspace/fw/src/main.c",
                "engineer.name@corp.example.com",
                "delinux03.de.moog.com",
                "10.20.30.40:8883",
                "Server=db01;Database=prod;User Id=svc;Password=x",
                "B99133-DV002-B-211b",
            )
        )
        present = {c.name for c in inventory.categories if c.samples}

        for expected in (
            "uri_scheme",
            "unc_path",
            "windows_path",
            "posix_path",
            "email_or_upn",
            "ip_address",
        ):
            assert expected in present, f"{expected} produced no samples"


class TestRanking:
    """Rarity is the signal. The interesting string appears once; the library
    constant appears three thousand times."""

    def test_rare_values_rank_above_common_ones(self) -> None:
        common = ["https://schemas.microsoft.com/winfx/2006/xaml"] * 12
        inventory = sweep(strings(SVN_STRING, *common))
        uris = inventory.category("uri_scheme")

        assert uris is not None
        assert "delinux03" in uris.samples[0]["value"]

    def test_ubiquitous_values_are_dropped(self) -> None:
        noise = ["https://schemas.example.com/ns"] * (UBIQUITY_THRESHOLD + 5)
        inventory = sweep(strings(SVN_STRING, *noise))
        uris = inventory.category("uri_scheme")

        assert uris is not None
        values = [s["value"] for s in uris.samples]
        assert not any("schemas.example.com" in v for v in values)
        assert any("delinux03" in v for v in values)

    def test_counts_are_preserved_even_when_samples_are_capped(self) -> None:
        noise = ["https://schemas.example.com/ns"] * (UBIQUITY_THRESHOLD + 5)
        inventory = sweep(strings(*noise))
        uris = inventory.category("uri_scheme")

        assert uris is not None
        assert uris.total == UBIQUITY_THRESHOLD + 5
        assert uris.distinct == 1


class TestCategoryPrecedence:
    def test_a_value_is_claimed_by_one_category_only(self) -> None:
        """A URI containing a hostname must not also be counted as a hostname,
        or every total becomes meaningless."""
        inventory = sweep(strings(SVN_STRING))
        matched = [c.name for c in inventory.categories if c.samples]
        assert matched == ["uri_scheme"]

    def test_bare_hostname_falls_to_the_hostname_sweep(self) -> None:
        inventory = sweep(strings("delinux03.de.moog.com"))
        assert inventory.category("hostname") is not None


class TestDeterminism:
    def test_identical_input_yields_identical_output(self) -> None:
        payload = strings(SVN_STRING, PROFILE_STRING, "a.b.example.com")
        first = sweep(payload).to_dict()
        second = sweep(payload).to_dict()
        assert first == second


class TestOutput:
    def test_inventory_is_never_a_finding(self) -> None:
        """Recon output carries no severity, no CWE, and no status — it is an
        inventory, and the type system should make that obvious."""
        inventory = sweep(strings(SVN_STRING))
        payload = inventory.to_dict()
        serialised = str(payload)

        for finding_field in ("severity", "cwe", "confidence", "status"):
            assert finding_field not in serialised

    def test_summary_renders(self) -> None:
        inventory = sweep(strings(SVN_STRING, PROFILE_STRING))
        text = summarise(inventory)
        assert "files swept" in text
        assert "uri_scheme" in text

    def test_empty_input_is_handled(self) -> None:
        inventory = sweep([])
        assert isinstance(inventory, ReconInventory)
        assert inventory.categories == []
