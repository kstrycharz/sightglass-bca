"""OpenAI and every endpoint that speaks its Chat Completions shape.

One adapter, many providers. OpenAI, Azure OpenAI, Groq, Together, OpenRouter,
Fireworks, DeepSeek, vLLM, and LM Studio all expose ``POST /v1/chat/completions``
with the same request and response bodies, so writing six near-identical
adapters would be six places to fix the next bug. The differences that do exist
are configuration — base URL, model name, and whether the key rides in a header
or a query string — not code.

The one real divergence is Azure, which puts the deployment in the path and the
API version in the query string. That is handled by letting the operator give a
full ``base_url`` rather than by special-casing a vendor here.
"""

from __future__ import annotations

from typing import Any

import structlog

from core.llm.provider import (
    DEFAULT_TIMEOUT_S,
    Capabilities,
    Completion,
    EgressPolicyGuard,
    LLMProvider,
    Message,
    ProviderHealth,
    timed,
)

log = structlog.get_logger(__name__)


class OpenAICompatibleProvider(LLMProvider):
    kind = "openai"

    def __init__(
        self,
        *,
        model: str,
        name: str = "openai",
        base_url: str = "https://api.openai.com/v1",
        api_key: str | None = None,
        guard: EgressPolicyGuard | None = None,
        context_window: int = 128_000,
        max_output_tokens: int = 4096,
    ) -> None:
        super().__init__(
            model=model,
            name=name,
            guard=guard or EgressPolicyGuard(allow_egress=False),
        )
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._context_window = context_window
        self._max_output_tokens = max_output_tokens

    @property
    def is_local(self) -> bool:
        """Whether plaintext could ever be sent to this endpoint.

        Keyed off the URL, not the vendor: a vLLM or LM Studio server on the
        operator's own network is local in every sense that matters here, and
        `api.openai.com` never is.
        """
        return self._guard.is_local(self.base_url)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"
        return headers

    def complete(
        self,
        messages: list[Message],
        *,
        json_mode: bool = False,
        max_tokens: int = 512,
        temperature: float = 0.0,
        timeout_s: int = DEFAULT_TIMEOUT_S,
    ) -> Completion:
        import httpx

        url = f"{self.base_url}/chat/completions"
        self._guard.check(url)

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "temperature": temperature,
            "max_tokens": max_tokens,
        }
        if json_mode:
            payload["response_format"] = {"type": "json_object"}

        started = timed()
        response = httpx.post(url, json=payload, headers=self._headers(), timeout=timeout_s)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        duration = timed() - started

        choices = data.get("choices") or [{}]
        message = choices[0].get("message") or {}
        text = (message.get("content") or "").strip()

        # Reasoning models on OpenAI-compatible endpoints expose their
        # deliberation as `reasoning_content` (DeepSeek, some vLLM builds).
        # Carried through under the same key the Ollama adapter uses so the
        # "spent its budget thinking" diagnosis works identically everywhere.
        thinking = (message.get("reasoning_content") or "").strip()

        usage = data.get("usage") or {}
        return Completion(
            text=text,
            model=data.get("model") or self.model,
            prompt_tokens=usage.get("prompt_tokens"),
            completion_tokens=usage.get("completion_tokens"),
            duration_s=round(duration, 3),
            raw={"thinking": thinking} if thinking else {},
        )

    def capabilities(self) -> Capabilities:
        return Capabilities(
            native_tool_calling=True,
            structured_output=True,
            context_window=self._context_window,
            max_output_tokens=self._max_output_tokens,
        )

    def health(self) -> ProviderHealth:
        import httpx

        try:
            self._guard.check(self.base_url)
        except Exception as exc:
            return ProviderHealth(healthy=False, provider=self.name, detail=str(exc))

        if not self._api_key and not self.is_local:
            return ProviderHealth(
                healthy=False,
                provider=self.name,
                model=self.model,
                detail="no API key configured for this provider",
            )

        try:
            started = timed()
            response = httpx.get(f"{self.base_url}/models", headers=self._headers(), timeout=15)
            response.raise_for_status()
            models = tuple(
                str(m.get("id")) for m in (response.json().get("data") or []) if m.get("id")
            )
            latency = timed() - started
        except Exception as exc:
            return ProviderHealth(
                healthy=False,
                provider=self.name,
                model=self.model,
                detail=f"cannot reach {self.base_url}: {_redact(exc, self._api_key)}",
            )

        # Not every compatible server lists models, and some list only a
        # subset. An empty or partial list is not evidence the model is
        # missing, so unlike Ollama this does not fail on absence.
        if models and self.model not in models:
            return ProviderHealth(
                healthy=True,
                provider=self.name,
                model=self.model,
                detail=(
                    f"reachable, but {self.model!r} was not in the endpoint's model list; "
                    "it may still work if the list is partial"
                ),
                latency_s=round(latency, 3),
                available_models=models,
            )

        return ProviderHealth(
            healthy=True,
            provider=self.name,
            model=self.model,
            detail=f"{len(models)} model(s) listed" if models else "reachable",
            latency_s=round(latency, 3),
            available_models=models,
        )


def _redact(exc: Exception, api_key: str | None) -> str:
    """Keep a key out of an error string.

    httpx puts the request URL in some exception messages, and a provider that
    takes its key in a query parameter would otherwise leak it into the logs
    and onto the settings page.
    """
    text = str(exc)
    if api_key and api_key in text:
        text = text.replace(api_key, "***")
    return text[:500]
