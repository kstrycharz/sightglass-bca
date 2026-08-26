"""Anthropic Messages API.

Its own adapter rather than the OpenAI-compatible one because three things
genuinely differ, and faking them through a shim would be more code than this:

* the system prompt is a top-level ``system`` field, not a message with
  ``role: "system"``;
* the key rides in ``x-api-key`` with an ``anthropic-version`` header, not in
  ``Authorization``;
* ``max_tokens`` is required, not optional.
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

API_VERSION = "2023-06-01"


class AnthropicProvider(LLMProvider):
    kind = "anthropic"

    def __init__(
        self,
        *,
        model: str,
        name: str = "anthropic",
        base_url: str = "https://api.anthropic.com/v1",
        api_key: str | None = None,
        guard: EgressPolicyGuard | None = None,
        context_window: int = 200_000,
        max_output_tokens: int = 8192,
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
        """Always False in practice — the redaction layer keys off this, and a
        hosted API must never be handed plaintext."""
        return self._guard.is_local(self.base_url)

    def _headers(self) -> dict[str, str]:
        headers = {
            "Content-Type": "application/json",
            "anthropic-version": API_VERSION,
        }
        if self._api_key:
            headers["x-api-key"] = self._api_key
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

        url = f"{self.base_url}/messages"
        self._guard.check(url)

        # System prompts are hoisted out of the turn list; everything else
        # keeps its order.
        system = "\n\n".join(m.content for m in messages if m.role == "system")
        turns = [
            {"role": m.role, "content": m.content} for m in messages if m.role != "system"
        ]

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": turns,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }
        if system:
            payload["system"] = system

        started = timed()
        response = httpx.post(url, json=payload, headers=self._headers(), timeout=timeout_s)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        duration = timed() - started

        # Content is a list of typed blocks; text and thinking arrive as
        # separate ones. Joining only the text blocks is what keeps a thinking
        # model's deliberation out of the answer.
        text_parts: list[str] = []
        thinking_parts: list[str] = []
        for block in data.get("content") or []:
            if not isinstance(block, dict):
                continue
            if block.get("type") == "text":
                text_parts.append(str(block.get("text", "")))
            elif block.get("type") == "thinking":
                thinking_parts.append(str(block.get("thinking", "")))

        usage = data.get("usage") or {}
        thinking = "\n".join(thinking_parts).strip()
        return Completion(
            text="\n".join(text_parts).strip(),
            model=data.get("model") or self.model,
            prompt_tokens=usage.get("input_tokens"),
            completion_tokens=usage.get("output_tokens"),
            duration_s=round(duration, 3),
            raw={"thinking": thinking} if thinking else {},
        )

    def capabilities(self) -> Capabilities:
        return Capabilities(
            native_tool_calling=True,
            # No response_format equivalent; JSON comes from prompting, which
            # every caller here already does.
            structured_output=False,
            context_window=self._context_window,
            max_output_tokens=self._max_output_tokens,
        )

    def health(self) -> ProviderHealth:
        import httpx

        try:
            self._guard.check(self.base_url)
        except Exception as exc:
            return ProviderHealth(healthy=False, provider=self.name, detail=str(exc))

        if not self._api_key:
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

        if models and self.model not in models:
            return ProviderHealth(
                healthy=False,
                provider=self.name,
                model=self.model,
                detail=f"model {self.model!r} is not available to this key",
                available_models=models,
            )

        return ProviderHealth(
            healthy=True,
            provider=self.name,
            model=self.model,
            detail=f"{len(models)} model(s) available",
            latency_s=round(latency, 3),
            available_models=models,
        )


def _redact(exc: Exception, api_key: str | None) -> str:
    text = str(exc)
    if api_key and api_key in text:
        text = text.replace(api_key, "***")
    return text[:500]
