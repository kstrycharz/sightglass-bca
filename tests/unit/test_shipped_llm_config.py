"""What `config/llm.yaml` is allowed to contain.

It is the *packaged default*: on first use it seeds the runtime copy in the data
volume, and the setup wizard and settings page write there afterwards. So a
provider committed to it is not an example — it is a host that every deployment
tries to reach on first boot, and whose address ships to everyone who clones the
repository.

That is exactly what happened: the file carried a developer's LAN Ollama box,
so a fresh install opened its settings page, probed a machine on somebody
else's network, and waited out the timeout twice before rendering.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

CONFIG = Path("config/llm.yaml")

# Loopback only. A private address is still somebody's machine; that it is
# unroutable from outside their LAN is what made the leak easy to miss, not
# what made it harmless.
LOOPBACK = re.compile(r"^(localhost|127(?:\.\d+){3}|\[::1\]|::1)$")

URL = re.compile(r"https?://([^/\s\"']+)")


@pytest.fixture
def document() -> dict[str, object]:
    parsed = yaml.safe_load(CONFIG.read_text(encoding="utf-8"))
    assert isinstance(parsed, dict)
    return parsed


class TestItShipsInert:
    def test_the_llm_layer_is_off(self, document: dict[str, object]) -> None:
        """`--no-llm` is the CI default and the pipeline is complete without a
        model (§2.5), so shipping enabled buys nothing and costs a probe."""
        assert document.get("enabled") is False

    def test_it_defines_no_providers(self, document: dict[str, object]) -> None:
        """The wizard writes providers to the runtime copy. Anything here is
        inherited by every deployment that never edits it."""
        assert not document.get("providers")

    def test_it_routes_no_roles(self, document: dict[str, object]) -> None:
        """Roles naming providers that do not exist would fail config load the
        moment somebody flipped `enabled` by hand."""
        assert not document.get("roles")

    def test_the_policy_still_ships(self, document: dict[str, object]) -> None:
        """Stripping the providers must not strip the guardrails with them."""
        policy = document.get("policy")
        assert isinstance(policy, dict)
        assert policy["egress"] == "deny"
        assert policy["redaction"] == "strict"


class TestNoOnesMachineIsInHere:
    def test_every_url_is_loopback(self) -> None:
        """Comments included. An example carrying a real address is copied into
        runtime configs verbatim, which is how this file acquired one."""
        text = CONFIG.read_text(encoding="utf-8")
        hosts = {match.split(":")[0] for match in URL.findall(text)}
        offenders = sorted(host for host in hosts if not LOOPBACK.match(host))
        assert offenders == [], (
            f"config/llm.yaml names non-loopback host(s) {offenders}; this file "
            "seeds every deployment's runtime config"
        )

    def test_it_loads_without_reaching_anything(self) -> None:
        """A disabled config skips validation entirely, so this is really a
        check that the file is still parseable YAML with the layer off."""
        from core.llm.router import load_config

        config = load_config(CONFIG)
        assert config.enabled is False
        assert config.providers == {}
