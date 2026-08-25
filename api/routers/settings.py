"""Settings: LLM provider configuration and live connection testing."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from api.deps import require_scope
from api.schemas.models import LlmSettingsOut, ProviderHealthOut
from core.auth import Scope
from core.llm import LLMConfigError, build_provider, load_config
from core.rules import load_rule_pack

router = APIRouter(
    prefix="/api/settings",
    tags=["settings"],
    dependencies=[Depends(require_scope(Scope.ADMIN))],
)


@router.get("/llm", response_model=LlmSettingsOut)
def get_llm_settings() -> LlmSettingsOut:
    """Current LLM configuration with a live health probe per provider.

    Probing on read rather than caching: "test connection" is the question
    being asked, and a stale green tick is worse than no tick.
    """
    try:
        config = load_config()
    except LLMConfigError as exc:
        # A config that would fail at request time fails here instead, which is
        # the whole point of validating at load (§8.2).
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from None

    providers: list[ProviderHealthOut] = []
    for name in sorted(config.providers):
        try:
            provider = build_provider(config, name)
            health = provider.health()
            providers.append(
                ProviderHealthOut(
                    name=name,
                    healthy=health.healthy,
                    model=health.model,
                    detail=health.detail,
                    latency_s=health.latency_s,
                    is_local=provider.is_local,
                    available_models=list(health.available_models),
                )
            )
        except Exception as exc:
            providers.append(ProviderHealthOut(name=name, healthy=False, detail=str(exc)[:300]))

    return LlmSettingsOut(
        enabled=config.enabled,
        egress=str(config.egress),
        redaction=config.redaction,
        roles=config.roles,
        providers=providers,
        config_path=str(config.path) if config.path else None,
    )


@router.get("/rules")
def get_rule_pack() -> dict[str, object]:
    """The loaded rule pack. Its hash is what the run manifest records."""
    from pathlib import Path

    from core.config import get_settings

    try:
        pack = load_rule_pack(Path(get_settings().repo_root) / "detections")
    except Exception as exc:
        raise HTTPException(status.HTTP_500_INTERNAL_SERVER_ERROR, str(exc)) from None

    return {
        "version": pack.version,
        "hash": pack.hash,
        "rule_count": len(pack.enabled_rules()),
        "false_positive_corpus_size": len(pack.false_positives),
        "rules": [
            {
                "id": rule.id,
                "name": rule.name,
                "category": rule.category,
                "severity": str(rule.severity),
                "confidence": rule.confidence,
                "cwe": rule.cwe,
                "description": rule.description,
                "tags": list(rule.tags),
            }
            for rule in pack.enabled_rules()
        ],
    }
