"""Role-based model routing.

Different jobs want different models, and on bandwidth-limited hardware the
difference is the whole ballgame. Triage runs over thousands of candidates and
wants a small, fast, non-reasoning model. Explanation runs over a handful of
confirmed findings and can afford a large one.

Config lives in ``config/llm.yaml`` and is hot-reloadable.
"""

from __future__ import annotations

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


def load_config(path: Path | None = None) -> LLMConfig:
    settings = get_settings()
    config_path = path or (Path(settings.repo_root) / DEFAULT_CONFIG_PATH)

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

    # Every other adapter (OpenAI, Anthropic, Google, Azure, Bedrock) lands in
    # M3. Failing by name is better than a generic KeyError three frames deep.
    raise NotImplementedError(
        f"provider kind {kind!r} is not implemented yet; only 'ollama' is available "
        "in M1. OpenAI, Anthropic, Google, Azure, and Bedrock adapters arrive in M3."
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
