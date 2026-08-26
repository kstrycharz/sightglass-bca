"""Google Gemini (Generative Language API).

Its own adapter: the model goes in the URL path, roles are ``user``/``model``
rather than ``user``/``assistant``, message text is nested under ``parts``, and
the system prompt is a separate ``systemInstruction`` object.

The key goes in the ``x-goog-api-key`` header rather than the ``?key=``
query parameter Google's own examples use. A key in a query string ends up in
proxy logs and error strings; for a product whose job is finding leaked
credentials, that is not a defensible default.
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


class GoogleProvider(LLMProvider):
    kind = "google"

    def __init__(
        self,
        *,
        model: str,
        name: str = "google",
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        api_key: str | None = None,
        guard: EgressPolicyGuard | None = None,
        context_window: int = 1_000_000,
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
        return self._guard.is_local(self.base_url)

    def _headers(self) -> dict[str, str]:
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["x-goog-api-key"] = self._api_key
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

        url = f"{self.base_url}/models/{self.model}:generateContent"
        self._guard.check(url)

        system = "\n\n".join(m.content for m in messages if m.role == "system")
        contents = [
            {
                # Gemini's assistant role is "model"; sending "assistant"
                # is a 400, not a warning.
                "role": "model" if m.role == "assistant" else "user",
                "parts": [{"text": m.content}],
            }
            for m in messages
            if m.role != "system"
        ]

        generation: dict[str, Any] = {
            "temperature": temperature,
            "maxOutputTokens": max_tokens,
        }
        if json_mode:
            generation["responseMimeType"] = "application/json"

        payload: dict[str, Any] = {"contents": contents, "generationConfig": generation}
        if system:
            payload["systemInstruction"] = {"parts": [{"text": system}]}

        started = timed()
        response = httpx.post(url, json=payload, headers=self._headers(), timeout=timeout_s)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        duration = timed() - started

        candidates = data.get("candidates") or [{}]
        parts = (candidates[0].get("content") or {}).get("parts") or []
        text = "\n".join(str(p.get("text", "")) for p in parts if isinstance(p, dict)).strip()

        usage = data.get("usageMetadata") or {}
        return Completion(
            text=text,
            model=self.model,
            prompt_tokens=usage.get("promptTokenCount"),
            completion_tokens=usage.get("candidatesTokenCount"),
            duration_s=round(duration, 3),
            # Gemini bills thinking under `thoughtsTokenCount` but does not
            # return the text, so there is nothing to carry through — an empty
            # answer here reports as an empty answer, which is the truth.
            raw={},
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
            # Names come back fully qualified ("models/gemini-2.0-flash"); the
            # bare id is what an operator configures.
            models = tuple(
                str(m.get("name", "")).removeprefix("models/")
                for m in (response.json().get("models") or [])
                if m.get("name")
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
