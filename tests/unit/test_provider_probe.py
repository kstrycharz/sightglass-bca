"""Probing providers for the settings page.

The page blocks on every provider before it renders, so two properties matter
and neither is about correctness of a single probe: the probes must not wait on
each other, and none of them may wait long. An endpoint that is *gone* — a host
off the network — black-holes the connection instead of refusing it, so the
wait is the timeout, per provider, every page load.
"""

from __future__ import annotations

import time

import pytest

from core.config import EgressPolicy
from core.llm.provider import HEALTH_TIMEOUT_S, ProviderHealth
from core.llm.router import LLMConfig, health_check_all, probe_provider

PROBE_DELAY_S = 0.3


class _SlowProvider:
    """Stands in for an unreachable host: answers only after a delay."""

    def __init__(self, name: str) -> None:
        self.name = name

    def health(self, *, timeout_s: float = HEALTH_TIMEOUT_S) -> ProviderHealth:
        time.sleep(PROBE_DELAY_S)
        return ProviderHealth(healthy=False, provider=self.name, detail="timed out")


def _config(count: int) -> LLMConfig:
    return LLMConfig(
        enabled=True,
        providers={f"p{i}": {"kind": "ollama", "model": "m"} for i in range(count)},
        roles={},
        egress=EgressPolicy.DENY,
    )


class TestTheTimeoutIsShort:
    def test_a_health_probe_does_not_use_the_completion_timeout(self) -> None:
        """120s is right for a scan and absurd for a page load."""
        from core.llm.provider import DEFAULT_TIMEOUT_S

        assert HEALTH_TIMEOUT_S < DEFAULT_TIMEOUT_S
        assert HEALTH_TIMEOUT_S <= 10

    def test_ollama_honours_the_timeout_it_is_given(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """It used to hard-code 15s, so the caller had no say."""
        import httpx

        from core.llm.providers.ollama import OllamaProvider

        seen: dict[str, float] = {}

        def fake_get(url: str, **kwargs: object) -> object:
            seen["timeout"] = float(kwargs["timeout"])  # type: ignore[arg-type]
            raise RuntimeError("no host")

        monkeypatch.setattr(httpx, "get", fake_get)
        provider = OllamaProvider(model="m", base_url="http://localhost:11434")
        provider.health(timeout_s=1.5)
        assert seen["timeout"] == 1.5


class TestProbesDoNotWaitOnEachOther:
    def test_four_slow_providers_cost_about_one_delay(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Serially this is 4 x PROBE_DELAY_S. That is the bug: the settings
        page took the sum of every unreachable provider's timeout."""
        monkeypatch.setattr(
            "core.llm.router.build_provider",
            lambda config, name: _SlowProvider(name),
        )
        started = time.monotonic()
        results = health_check_all(_config(4))
        elapsed = time.monotonic() - started

        assert len(results) == 4
        serial = PROBE_DELAY_S * 4
        assert elapsed < serial / 2, f"probes took {elapsed:.2f}s; serial would be {serial:.2f}s"

    def test_every_provider_is_reported(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Concurrency must not drop or reorder results against their names."""
        monkeypatch.setattr(
            "core.llm.router.build_provider",
            lambda config, name: _SlowProvider(name),
        )
        results = health_check_all(_config(3))
        assert sorted(results) == ["p0", "p1", "p2"]
        for name, health in results.items():
            assert health.provider == name

    def test_no_providers_is_not_an_error(self) -> None:
        assert health_check_all(_config(0)) == {}


class TestAProviderThatCannotBeBuilt:
    def test_it_reports_unhealthy_rather_than_raising(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The settings page has to render either way; an unknown provider kind
        is as unhealthy as one that will not answer."""

        def explode(config: object, name: str) -> object:
            raise ValueError("unknown kind 'wat'")

        monkeypatch.setattr("core.llm.router.build_provider", explode)
        health = probe_provider(_config(1), "p0")
        assert health.healthy is False
        assert "unknown kind" in (health.detail or "")
