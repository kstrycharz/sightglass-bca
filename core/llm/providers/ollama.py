"""Ollama adapter — the default, local provider.

Two Ollama-specific details that cost time if you do not know them:

* **Reasoning models return a separate ``thinking`` field.** GLM, DeepSeek-R1,
  and Qwen's thinking variants put their deliberation there and leave
  ``content`` empty until the reasoning finishes. A token budget sized for the
  answer therefore yields an empty response with no error. The adapter detects
  this and says so, rather than reporting a blank verdict.

* **First call to a cold model includes load time.** A 9 GB model can take 20+
  seconds to page in and then answer in two. Health checks warm the model so
  the first real triage call is not mistaken for a slow one.
"""

from __future__ import annotations

from typing import Any

import structlog

from core.llm.provider import (
    DEFAULT_TIMEOUT_S,
    HEALTH_TIMEOUT_S,
    Capabilities,
    Completion,
    EgressPolicyGuard,
    LLMProvider,
    Message,
    ProviderHealth,
    timed,
)

log = structlog.get_logger(__name__)


class OllamaProvider(LLMProvider):
    kind = "ollama"

    def __init__(
        self,
        *,
        model: str,
        name: str = "ollama",
        base_url: str = "http://localhost:11434",
        guard: EgressPolicyGuard | None = None,
        num_ctx: int | None = None,
    ) -> None:
        super().__init__(
            model=model,
            name=name,
            guard=guard or EgressPolicyGuard(allow_egress=False),
        )
        self.base_url = base_url.rstrip("/")
        self._num_ctx = num_ctx
        self._capabilities: Capabilities | None = None

    @property
    def is_local(self) -> bool:
        return self._guard.is_local(self.base_url)

    def _post(self, path: str, payload: dict[str, Any], timeout_s: int) -> dict[str, Any]:
        import httpx

        url = f"{self.base_url}{path}"
        self._guard.check(url)
        response = httpx.post(url, json=payload, timeout=timeout_s)
        response.raise_for_status()
        data: dict[str, Any] = response.json()
        return data

    def complete(
        self,
        messages: list[Message],
        *,
        json_mode: bool = False,
        max_tokens: int = 512,
        temperature: float = 0.0,
        timeout_s: int = DEFAULT_TIMEOUT_S,
    ) -> Completion:
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": [{"role": m.role, "content": m.content} for m in messages],
            "stream": False,
            "options": {"temperature": temperature, "num_predict": max_tokens},
        }
        if self._num_ctx:
            payload["options"]["num_ctx"] = self._num_ctx
        if json_mode:
            payload["format"] = "json"

        started = timed()
        data = self._post("/api/chat", payload, timeout_s)
        duration = timed() - started

        message = data.get("message", {}) or {}
        text = (message.get("content") or "").strip()
        thinking = (message.get("thinking") or "").strip()

        if not text and thinking:
            # The model spent its whole budget reasoning. Reporting this as an
            # empty answer would look like a model failure; it is a budget
            # problem, and the operator needs to know which.
            log.warning(
                "ollama.reasoning_exhausted_budget",
                model=self.model,
                max_tokens=max_tokens,
                thinking_chars=len(thinking),
            )

        return Completion(
            text=text,
            model=self.model,
            prompt_tokens=data.get("prompt_eval_count"),
            completion_tokens=data.get("eval_count"),
            duration_s=round(duration, 3),
            raw={"thinking": thinking} if thinking else {},
        )

    def capabilities(self) -> Capabilities:
        if self._capabilities is not None:
            return self._capabilities

        context_window = 8192
        try:
            data = self._post("/api/show", {"model": self.model}, 30)
            for key, value in (data.get("model_info") or {}).items():
                if key.endswith(".context_length"):
                    context_window = int(value)
                    break
        except Exception as exc:
            log.debug("ollama.capabilities_probe_failed", error=str(exc))

        self._capabilities = Capabilities(
            # Ollama exposes tool calling, but small local models use it
            # unreliably; the triage path uses JSON mode, which they handle far
            # better. Deep Investigation (M5) falls back to a prompted ReAct
            # loop rather than trusting this.
            native_tool_calling=False,
            structured_output=True,
            context_window=context_window,
            max_output_tokens=4096,
        )
        return self._capabilities

    def health(self, *, timeout_s: float = HEALTH_TIMEOUT_S) -> ProviderHealth:
        import httpx

        try:
            self._guard.check(self.base_url)
        except Exception as exc:
            return ProviderHealth(healthy=False, provider=self.name, detail=str(exc))

        try:
            started = timed()
            response = httpx.get(f"{self.base_url}/api/tags", timeout=timeout_s)
            response.raise_for_status()
            models = tuple(m["name"] for m in response.json().get("models", []))
            latency = timed() - started
        except Exception as exc:
            return ProviderHealth(
                healthy=False,
                provider=self.name,
                model=self.model,
                detail=f"cannot reach Ollama at {self.base_url}: {exc}",
            )

        if self.model not in models:
            return ProviderHealth(
                healthy=False,
                provider=self.name,
                model=self.model,
                detail=f"model {self.model!r} is not pulled; run: ollama pull {self.model}",
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

    def warm(self, timeout_s: int = 900) -> float | None:
        """Page the model into memory and return how long it took.

        Worth doing before a triage pass. On a bandwidth-bound box a 9 GB model
        takes 20+ seconds to load and then answers in two — and without an
        explicit warm-up, that load time lands on the first candidate and looks
        like the model is unusably slow.
        """
        started = timed()
        try:
            self._post(
                "/api/chat",
                {
                    "model": self.model,
                    "messages": [{"role": "user", "content": "ok"}],
                    "stream": False,
                    "options": {"num_predict": 1},
                },
                timeout_s,
            )
        except Exception as exc:
            log.warning("ollama.warm_failed", model=self.model, error=str(exc))
            return None
        elapsed = round(timed() - started, 2)
        log.info("ollama.warmed", model=self.model, seconds=elapsed)
        return elapsed
