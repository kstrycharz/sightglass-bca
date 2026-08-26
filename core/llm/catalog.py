"""The providers the setup wizard offers, and what each one needs.

Data, not code. Every entry here is something the existing adapters already
speak — this file only supplies the base URL, a sensible default model, and the
handful of words an operator needs to decide. Adding a vendor that talks the
OpenAI shape means adding a row, not writing an adapter.

Model defaults are chosen for the `triage` role, which is the one that runs
thousands of times per scan: small, fast, cheap, non-reasoning. A reasoning
model here is the single most common way to make Sightglass look broken — it
spends its whole token budget deliberating and returns nothing.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, slots=True)
class CatalogEntry:
    id: str
    label: str
    kind: str
    """Which adapter speaks this. See core.llm.router.build_provider."""
    base_url: str
    default_model: str
    requires_key: bool
    is_local: bool
    """Whether this runs on the operator's own hardware. Drives the egress
    warning, and whether plaintext could ever be sent under an explicit opt-in."""
    summary: str
    key_hint: str = ""
    key_url: str = ""
    suggested_models: tuple[str, ...] = field(default_factory=tuple)


CATALOG: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        id="ollama",
        label="Ollama (local)",
        kind="ollama",
        base_url="http://localhost:11434",
        default_model="qwen2.5-coder:7b-instruct-q4_K_M",
        requires_key=False,
        is_local=True,
        summary=(
            "Runs on your own hardware. Nothing leaves your network, which is the "
            "only option that keeps an air-gapped deployment air-gapped."
        ),
        suggested_models=(
            "qwen2.5-coder:7b-instruct-q4_K_M",
            "qwen2.5-coder:14b-instruct-q4_K_M",
            "llama3.2:3b",
        ),
    ),
    CatalogEntry(
        id="vllm",
        label="vLLM / LM Studio (local)",
        kind="openai",
        base_url="http://localhost:8000/v1",
        default_model="",
        requires_key=False,
        is_local=True,
        summary=(
            "Any server that speaks the OpenAI chat API on your own network. "
            "Faster than Ollama at volume, and the same privacy position."
        ),
    ),
    CatalogEntry(
        id="openai",
        label="OpenAI",
        kind="openai",
        base_url="https://api.openai.com/v1",
        default_model="gpt-4o-mini",
        requires_key=True,
        is_local=False,
        summary="Hosted. Fast and inexpensive at triage volume.",
        key_hint="Starts with sk-",
        key_url="https://platform.openai.com/api-keys",
        suggested_models=("gpt-4o-mini", "gpt-4o"),
    ),
    CatalogEntry(
        id="anthropic",
        label="Anthropic",
        kind="anthropic",
        base_url="https://api.anthropic.com/v1",
        default_model="claude-haiku-4-5-20251001",
        requires_key=True,
        is_local=False,
        summary="Hosted. Haiku for triage volume, Sonnet for explanations.",
        key_hint="Starts with sk-ant-",
        key_url="https://console.anthropic.com/settings/keys",
        suggested_models=("claude-haiku-4-5-20251001", "claude-sonnet-4-5-20250929"),
    ),
    CatalogEntry(
        id="google",
        label="Google Gemini",
        kind="google",
        base_url="https://generativelanguage.googleapis.com/v1beta",
        default_model="gemini-2.0-flash",
        requires_key=True,
        is_local=False,
        summary="Hosted. Flash models are well suited to triage volume.",
        key_url="https://aistudio.google.com/apikey",
        suggested_models=("gemini-2.0-flash", "gemini-2.5-flash"),
    ),
    CatalogEntry(
        id="groq",
        label="Groq",
        kind="openai",
        base_url="https://api.groq.com/openai/v1",
        default_model="llama-3.3-70b-versatile",
        requires_key=True,
        is_local=False,
        summary="Hosted, OpenAI-compatible. Very low latency per call.",
        key_hint="Starts with gsk_",
        key_url="https://console.groq.com/keys",
    ),
    CatalogEntry(
        id="openrouter",
        label="OpenRouter",
        kind="openai",
        base_url="https://openrouter.ai/api/v1",
        default_model="openai/gpt-4o-mini",
        requires_key=True,
        is_local=False,
        summary="Hosted gateway to many vendors behind one OpenAI-compatible key.",
        key_hint="Starts with sk-or-",
        key_url="https://openrouter.ai/keys",
    ),
    CatalogEntry(
        id="azure-openai",
        label="Azure OpenAI",
        kind="openai",
        base_url="",
        default_model="",
        requires_key=True,
        is_local=False,
        summary=(
            "Hosted in your own Azure tenant. Give the full deployment URL, "
            "including the api-version query string."
        ),
        key_hint="Your Azure OpenAI key",
    ),
)

BY_ID: dict[str, CatalogEntry] = {entry.id: entry for entry in CATALOG}
