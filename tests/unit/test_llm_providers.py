"""Cloud provider adapters and the API key store.

The tests that matter here are about where a key ends up. `config/llm.yaml` is
a committed file, so a provider key written into it is a credential in the
repository — exactly the failure this product exists to find in other people's
artifacts.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
import yaml

from core.llm import secrets
from core.llm.catalog import BY_ID, CATALOG
from core.llm.provider import EgressPolicyGuard, Message
from core.llm.providers.anthropic import AnthropicProvider
from core.llm.providers.google import GoogleProvider
from core.llm.providers.openai_compatible import OpenAICompatibleProvider
from core.llm.router import LLMConfig, LLMConfigError, build_provider
from core.llm.settings_writer import LlmUpdate, NewProvider, apply_update

KEY = "sk-not-a-real-key-0123456789"


@pytest.fixture
def store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    path = tmp_path / "llm-keys.json"
    monkeypatch.setenv("SIGHTGLASS_LLM_KEY_STORE", str(path))
    yield path


class TestKeysStayOutOfTheConfig:
    def test_a_new_provider_writes_no_key_into_the_yaml(self, tmp_path: Path) -> None:
        """The single most important property here.

        `egress` is set alongside because `apply_update` validates the result
        it is about to write, and a hosted provider under the default deny
        policy is a config that would fail at scan time. The wizard endpoint
        sets both together for exactly this reason.
        """
        config = tmp_path / "llm.yaml"
        config.write_text(
            yaml.safe_dump({"enabled": True, "providers": {}, "roles": {}}),
            encoding="utf-8",
        )

        apply_update(
            LlmUpdate(
                add_provider=NewProvider(
                    name="openai", kind="openai", model="gpt-4o-mini",
                    base_url="https://api.openai.com/v1",
                ),
                egress="allow",
            ),
            path=config,
        )

        text = config.read_text(encoding="utf-8")
        assert KEY not in text
        assert "api_key" not in text
        assert "gpt-4o-mini" in text

    def test_a_hosted_provider_is_refused_under_the_deny_policy(
        self, tmp_path: Path
    ) -> None:
        """The control working. A config that would be blocked at request time
        is refused at write time, with nothing changed on disk."""
        config = tmp_path / "llm.yaml"
        original = yaml.safe_dump({"enabled": True, "providers": {}, "roles": {}})
        config.write_text(original, encoding="utf-8")

        with pytest.raises(LLMConfigError, match="egress"):
            apply_update(
                LlmUpdate(
                    add_provider=NewProvider(
                        name="openai", kind="openai", model="gpt-4o-mini",
                        base_url="https://api.openai.com/v1",
                    )
                ),
                path=config,
            )

        assert config.read_text(encoding="utf-8") == original

    def test_the_store_holds_the_key_not_the_config(self, store: Path) -> None:
        secrets.set_api_key("openai", KEY)
        assert secrets.resolve_api_key("openai", {}) == KEY
        assert KEY in store.read_text(encoding="utf-8")

    def test_an_env_var_wins_over_the_store(
        self, store: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """A real deployment injects the key like every other secret; the store
        exists only so the wizard does not require hand-editing files."""
        secrets.set_api_key("openai", "from-store")
        monkeypatch.setenv("MY_OPENAI_KEY", "from-env")
        resolved = secrets.resolve_api_key("openai", {"api_key_env": "MY_OPENAI_KEY"})
        assert resolved == "from-env"

    def test_an_empty_env_var_falls_through_to_the_store(
        self, store: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """An exported-but-blank variable is the usual shape of a broken
        deployment; treating it as "configured" would mean sending no key."""
        secrets.set_api_key("openai", "from-store")
        monkeypatch.setenv("MY_OPENAI_KEY", "   ")
        assert secrets.resolve_api_key("openai", {"api_key_env": "MY_OPENAI_KEY"}) == "from-store"

    def test_a_missing_store_is_not_an_error(self, store: Path) -> None:
        """No model configured is the default state of this product."""
        assert secrets.resolve_api_key("openai", {}) is None

    def test_a_corrupt_store_does_not_raise(self, store: Path) -> None:
        store.write_text("{ not json", encoding="utf-8")
        assert secrets.resolve_api_key("openai", {}) is None

    def test_forgetting_a_key_removes_it(self, store: Path) -> None:
        secrets.set_api_key("openai", KEY)
        assert secrets.forget_api_key("openai") is True
        assert secrets.resolve_api_key("openai", {}) is None
        assert KEY not in store.read_text(encoding="utf-8")


class TestRuntimeConfigSurvivesARebuild:
    """Everything under `repo_root` is baked into the image, so a config the
    wizard wrote there would be discarded by the next `docker compose build` —
    silently, taking the operator's provider choice with it."""

    def test_the_live_config_is_not_the_packaged_one(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from core.config import get_settings
        from core.llm.router import active_config_path

        monkeypatch.setenv("SIGHTGLASS_DATA_DIR", str(tmp_path / "data"))
        monkeypatch.setenv("SIGHTGLASS_REPO_ROOT", str(tmp_path / "repo"))
        monkeypatch.delenv("SIGHTGLASS_LLM_CONFIG", raising=False)
        get_settings.cache_clear()

        active = active_config_path()
        assert (tmp_path / "repo") not in active.parents
        assert (tmp_path / "data") in active.parents
        get_settings.cache_clear()

    def test_it_is_seeded_from_the_packaged_default_once(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from core.config import get_settings
        from core.llm.router import ensure_runtime_config

        repo = tmp_path / "repo"
        (repo / "config").mkdir(parents=True)
        (repo / "config" / "llm.yaml").write_text(
            yaml.safe_dump({"enabled": False, "providers": {}, "roles": {}}),
            encoding="utf-8",
        )
        monkeypatch.setenv("SIGHTGLASS_DATA_DIR", str(tmp_path / "data"))
        monkeypatch.setenv("SIGHTGLASS_REPO_ROOT", str(repo))
        monkeypatch.delenv("SIGHTGLASS_LLM_CONFIG", raising=False)
        get_settings.cache_clear()

        first = ensure_runtime_config()
        assert first.is_file()

        # An operator edit must not be clobbered by the next seed attempt.
        first.write_text(
            yaml.safe_dump({"enabled": True, "providers": {}, "roles": {}}),
            encoding="utf-8",
        )
        second = ensure_runtime_config()
        assert yaml.safe_load(second.read_text(encoding="utf-8"))["enabled"] is True
        get_settings.cache_clear()


class TestKeysStayOutOfErrors:
    """An error string reaches the settings page and the logs."""

    @pytest.mark.parametrize(
        "provider_class",
        [OpenAICompatibleProvider, AnthropicProvider, GoogleProvider],
    )
    def test_health_failure_does_not_echo_the_key(self, provider_class: type) -> None:
        provider = provider_class(
            model="m",
            name="p",
            base_url="http://127.0.0.1:1/v1",  # refused instantly
            api_key=KEY,
            guard=EgressPolicyGuard(allow_egress=True),
        )
        health = provider.health()
        assert not health.healthy
        assert KEY not in health.detail


class TestWireShapes:
    """Each adapter exists because its provider's shape genuinely differs."""

    def test_anthropic_hoists_the_system_prompt(self) -> None:
        """Anthropic takes `system` as a top-level field; sending it as a
        message role is a 400."""
        captured: dict = {}

        class Fake(AnthropicProvider):
            def complete(self, messages, **kwargs):  # type: ignore[no-untyped-def]
                system = "\n\n".join(m.content for m in messages if m.role == "system")
                turns = [m for m in messages if m.role != "system"]
                captured["system"] = system
                captured["turns"] = turns
                raise RuntimeError("stop here")

        provider = Fake(model="m", api_key=KEY, guard=EgressPolicyGuard(allow_egress=True))
        with pytest.raises(RuntimeError):
            provider.complete([Message("system", "rules"), Message("user", "hi")])

        assert captured["system"] == "rules"
        assert all(m.role != "system" for m in captured["turns"])

    def test_google_uses_the_header_not_a_query_parameter(self) -> None:
        """A key in a query string lands in proxy logs and error strings."""
        provider = GoogleProvider(
            model="gemini-2.0-flash", api_key=KEY, guard=EgressPolicyGuard(allow_egress=True)
        )
        headers = provider._headers()
        assert headers["x-goog-api-key"] == KEY

    def test_openai_uses_a_bearer_header(self) -> None:
        provider = OpenAICompatibleProvider(
            model="gpt-4o-mini", api_key=KEY, guard=EgressPolicyGuard(allow_egress=True)
        )
        assert provider._headers()["Authorization"] == f"Bearer {KEY}"


class TestLocality:
    """`is_local` is what the redaction layer keys off, so it is keyed to the
    URL rather than to the vendor: a vLLM box on the LAN is local, and
    api.openai.com never is."""

    def test_a_hosted_endpoint_is_never_local(self) -> None:
        provider = OpenAICompatibleProvider(
            model="m",
            base_url="https://api.openai.com/v1",
            guard=EgressPolicyGuard(allow_egress=True),
        )
        assert provider.is_local is False

    def test_an_openai_compatible_server_on_the_lan_is_local(self) -> None:
        provider = OpenAICompatibleProvider(
            model="m",
            base_url="http://192.168.1.50:8000/v1",
            guard=EgressPolicyGuard(allow_egress=True),
        )
        assert provider.is_local is True


class TestCatalogMatchesTheAdapters:
    def test_every_catalog_kind_can_actually_be_built(self) -> None:
        """A catalog entry whose `kind` no adapter implements is a wizard that
        offers a provider it cannot connect."""
        for entry in CATALOG:
            config = LLMConfig(
                enabled=True,
                providers={
                    entry.id: {
                        "kind": entry.kind,
                        "model": entry.default_model or "placeholder",
                        "base_url": entry.base_url or "http://localhost:1234/v1",
                    }
                },
                roles={},
                egress="allow",
                path=Path("llm.yaml"),
            )
            provider = build_provider(config, entry.id)
            assert provider.kind

    def test_ids_are_unique(self) -> None:
        assert len(BY_ID) == len(CATALOG)

    def test_hosted_entries_declare_they_need_a_key(self) -> None:
        for entry in CATALOG:
            if not entry.is_local:
                assert entry.requires_key, f"{entry.id} is hosted but claims no key"
