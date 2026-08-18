"""BYOLLM layer: provider adapters, egress policy, routing, triage.

Advisory by construction. Nothing here can create a finding; see core.llm.triage.
"""

from core.llm.discovery import DiscoveryResult, RuleProposal, discover_rules, proposals_to_yaml
from core.llm.provider import (
    Capabilities,
    Completion,
    EgressBlocked,
    EgressPolicyGuard,
    LLMProvider,
    Message,
    ProviderHealth,
)
from core.llm.router import (
    LLMConfig,
    LLMConfigError,
    build_provider,
    health_check_all,
    load_config,
    provider_for_role,
)
from core.llm.triage import TriageResult, apply_verdict, build_prompt, triage_finding, triage_run

__all__ = [
    "Capabilities",
    "Completion",
    "DiscoveryResult",
    "EgressBlocked",
    "EgressPolicyGuard",
    "LLMConfig",
    "LLMConfigError",
    "LLMProvider",
    "Message",
    "ProviderHealth",
    "RuleProposal",
    "TriageResult",
    "apply_verdict",
    "build_prompt",
    "build_provider",
    "discover_rules",
    "health_check_all",
    "load_config",
    "proposals_to_yaml",
    "provider_for_role",
    "triage_finding",
    "triage_run",
]
