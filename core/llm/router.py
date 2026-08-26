"""Role-based model routing.

Different jobs want different models, and on bandwidth-limited hardware the
difference is the whole ballgame. Triage runs over thousands of candidates and
wants a small, fast, non-reasoning model. Explanation runs over a handful of
confirmed findings and can afford a large one.

Config lives in ``config/llm.yaml`` and is hot-reloadable.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import structlog
import yaml

from core.config import EgressPolicy, get_settings
from core.llm.provider import EgressPolicyGuard, LLMProvider, ProviderHealth

log = structlog.get_logger(__name__)

DEFAULT_CONFIG_PATH = Path("config/llm.yaml")
ROLES = ("triage", "explain", "remediate", "summarize")


class LLMConfigError(ValueError):
    """A configuration that would fail at request time. Raised at load instead.

    An air-gapped deployment must discover it has been pointed at a cloud
    provider when an operator reads the startup logs, not when a scan is
    halfway through.
    """


@dataclass(slots=True)
class LLMConfig:
    enabled: bool
    providers: dict[str, dict[str, Any]]
    roles: dict[str, str]
    egress: EgressPolicy
    redaction: str = "strict"
    allowed_hosts: tuple[str, ...] = ()
    path: Path | None = None

    def provider_for(self, role: str) -> str:
        name = self.roles.get(role)
        if name is None:
            raise LLMConfigError(f"no provider configured for role {role!r}")
        if name not in self.providers:
            raise LLMConfigError(f"role {role!r} points at provider {name!r}, which is not defined")
        return name


def active_config_path() -> Path:
    """Where the live LLM config is read from and written to.

    Not the copy baked into the image. `config/llm.yaml` ships as the *default*,
    but the settings page and the setup wizard write to this file at runtime,
    and an image-local path means every `docker compose build` silently throws
    those edits away — which would make configuring a provider through the UI
    pointless. The runtime copy lives in a volume and is seeded from the image
    default on first use (see `ensure_runtime_config`).
    """
    override = os.environ.get("SIGHTGLASS_LLM_CONFIG")
    if override:
        return Path(override)
    return Path(get_settings().data_dir) / "llm.yaml"


def ensure_runtime_config() -> Path:
    """Seed the runtime config from the image default, once.

    Copied rather than symlinked so the shipped default stays readable as a
    reference, and so an operator can delete the runtime copy to get it back.
    """
    active = active_config_path()
    if active.is_file():
        return active

    packaged = Path(get_settings().repo_root) / DEFAULT_CONFIG_PATH
    active.parent.mkdir(parents=True, exist_ok=True)
    if packaged.is_file():
        active.write_text(packaged.read_text(encoding="utf-8"), encoding="utf-8")
        log.info("llm.config_seeded", source=str(packaged), target=str(active))
    return active


def load_config(path: Path | None = None) -> LLMConfig:
    settings = get_settings()
    config_path = path or ensure_runtime_config()

    if not config_path.is_file():
        # Absent config is not an error: the deterministic pipeline is the
        # default and must work with no model configured at all (§2.5).
        return LLMConfig(
            enabled=False,
            providers={},
            roles={},
            egress=settings.egress_policy,
            path=config_path,
        )

    document = yaml.safe_load(config_path.read_text(encoding="utf-8")) or {}
    policy = document.get("policy", {}) or {}
    egress = EgressPolicy(policy.get("egress", settings.egress_policy))

    config = LLMConfig(
        enabled=bool(document.get("enabled", True)),
        providers=document.get("providers", {}) or {},
        roles=document.get("roles", {}) or {},
        egress=egress,
        redaction=policy.get("redaction", "strict"),
        allowed_hosts=tuple(policy.get("allowed_hosts", ()) or ()),
        path=config_path,
    )
    _validate(config, air_gapped=settings.air_gapped)
    return config


def _validate(config: LLMConfig, *, air_gapped: bool) -> None:
    if not config.enabled:
        return

    for role in ROLES:
        if role in config.roles:
            config.provider_for(role)  # raises if the target is undefined

    guard = EgressPolicyGuard(
        allow_egress=config.egress is EgressPolicy.ALLOW,
        air_gapped=air_gapped,
        allowed_hosts=config.allowed_hosts,
    )
    for name, spec in config.providers.items():
        base_url = spec.get("base_url")
        if not base_url:
            continue
        try:
            guard.check(base_url)
        except Exception as exc:
            raise LLMConfigError(
                f"provider {name!r} would be blocked by the egress policy: {exc}"
            ) from None


def build_guard(config: LLMConfig) -> EgressPolicyGuard:
    settings = get_settings()
    return EgressPolicyGuard(
        allow_egress=config.egress is EgressPolicy.ALLOW,
        air_gapped=settings.air_gapped,
        allowed_hosts=config.allowed_hosts,
    )


def build_provider(config: LLMConfig, name: str) -> LLMProvider:
    spec = config.providers.get(name)
    if spec is None:
        raise LLMConfigError(f"provider {name!r} is not defined in {config.path}")

    kind = spec.get("kind", "ollama")
    guard = build_guard(config)

    if kind == "ollama":
        from core.llm.providers.ollama import OllamaProvider

        return OllamaProvider(
            model=spec["model"],
            name=name,
            base_url=spec.get("base_url", "http://localhost:11434"),
            guard=guard,
            num_ctx=spec.get("num_ctx"),
        )

    # The key is never read from `spec` — it resolves from the environment or
    # the runtime key store, so it cannot end up in config/llm.yaml, which is
    # a committed file. See core.llm.secrets.
    from core.llm.secrets import resolve_api_key

    api_key = resolve_api_key(name, spec)

    if kind in ("openai", "openai_compatible", "azure", "vllm"):
        # One adapter for every endpoint that speaks the OpenAI chat shape.
        # The aliases exist because operators reach for the vendor's name.
        from core.llm.providers.openai_compatible import OpenAICompatibleProvider

        return OpenAICompatibleProvider(
            model=spec["model"],
            name=name,
            base_url=spec.get("base_url", "https://api.openai.com/v1"),
            api_key=api_key,
            guard=guard,
        )

    if kind == "anthropic":
        from core.llm.providers.anthropic import AnthropicProvider

        return AnthropicProvider(
            model=spec["model"],
            name=name,
            base_url=spec.get("base_url", "https://api.anthropic.com/v1"),
            api_key=api_key,
            guard=guard,
        )

    if kind in ("google", "gemini"):
        from core.llm.providers.google import GoogleProvider

        return GoogleProvider(
            model=spec["model"],
            name=name,
            base_url=spec.get(
                "base_url", "https://generativelanguage.googleapis.com/v1beta"
            ),
            api_key=api_key,
            guard=guard,
        )

    # Bedrock still lands later: it authenticates with SigV4 rather than a
    # bearer token, so it needs credential handling none of the above share.
    # Failing by name beats a generic KeyError three frames deep.
    raise NotImplementedError(
        f"provider kind {kind!r} is not implemented. Available: 'ollama', 'openai' "
        "(and any OpenAI-compatible endpoint), 'anthropic', 'google'. "
        "Bedrock arrives with SigV4 support."
    )


def provider_for_role(role: str, config: LLMConfig | None = None) -> LLMProvider:
    config = config or load_config()
    if not config.enabled:
        raise LLMConfigError("the LLM layer is disabled")
    return build_provider(config, config.provider_for(role))


def health_check_all(config: LLMConfig | None = None) -> dict[str, ProviderHealth]:
    """Probe every configured provider. Drives the settings page."""
    config = config or load_config()
    results: dict[str, ProviderHealth] = {}
    for name in config.providers:
        try:
            results[name] = build_provider(config, name).health()
        except Exception as exc:
            results[name] = ProviderHealth(healthy=False, provider=name, detail=str(exc))
    return results
