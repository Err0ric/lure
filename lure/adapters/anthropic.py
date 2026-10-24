"""Anthropic adapter, using the official SDK's Messages API.

The API key comes from ANTHROPIC_API_KEY, loaded from .env in the current
directory if it is not already set in the environment.

Effort is sent explicitly (default medium) so runs are comparable across
models whose own defaults differ. Pass effort=None to use the model default.

Refusal fallbacks are deliberately not enabled: a fallback would answer
with a different model than the one under test.
"""

from __future__ import annotations

from typing import Any

import anthropic
import httpx2
from dotenv import find_dotenv, load_dotenv

from lure.adapters.base import (
    USAGE_KEYS,
    AdapterError,
    Conversation,
    ModelAdapter,
    ModelTurn,
    ToolCallRequest,
    ToolResult,
    ToolSpec,
)

DEFAULT_MODEL = "claude-haiku-5-5"  # cheap default for test runs
DEFAULT_EFFORT = "medium"
DEFAULT_MAX_TOKENS = 16000


class AnthropicAdapter(ModelAdapter):
    provider = "anthropic"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        api_key: str | None = None,
        effort: str | None = DEFAULT_EFFORT,
        max_tokens: int = DEFAULT_MAX_TOKENS,
        timeout: float = 600.0,
        max_retries: int = 2,
        transport: httpx2.BaseTransport | None = None,
    ) -> None:
        super().__init__(model)
        load_dotenv(find_dotenv(usecwd=True), override=False)
        self.effort = effort
        self.max_tokens = max_tokens
        http_client = (
            anthropic.DefaultHttpxClient(transport=transport) if transport else None
        )
        try:
            self._client = anthropic.Anthropic(
                api_key=api_key,
                timeout=timeout,
                max_retries=max_retries,
                http_client=http_client,
            )
        except anthropic.AnthropicError as e:
            raise AdapterError(
                f"no Anthropic credentials: set ANTHROPIC_API_KEY in .env ({e})"
            ) from e

    def start(self, system: str, tools: list[ToolSpec]) -> AnthropicConversation:
        return AnthropicConversation(self, system, tools)

    def create(self, **params: Any) -> anthropic.types.Message:
        if self.effort:
            params["output_config"] = {**params.get("output_config", {}), "effort": self.effort}
        try:
            return self._client.messages.create(
                model=self.model, max_tokens=self.max_tokens, **params
            )
        except anthropic.APIStatusError as e:
            raise AdapterError(
                f"anthropic API returned HTTP {e.status_code}: {e.message}"
            ) from e
        except anthropic.APIConnectionError as e:
            raise AdapterError(f"anthropic API connection failed: {e}") from e


class AnthropicConversation(Conversation):
    def __init__(
        self, adapter: AnthropicAdapter, system: str, tools: list[ToolSpec]
    ) -> None:
        self._adapter = adapter
        self._system = system
        self.set_tools(tools)
        self.messages: list[dict[str, Any]] = []
        self._schema: dict[str, Any] | None = None

    def set_tools(self, tools: list[ToolSpec]) -> None:
        self._tools = [
            {"name": t.name, "description": t.description, "input_schema": t.parameters}
            for t in tools
        ]

    def set_output_schema(self, schema: dict[str, Any]) -> None:
        self._schema = schema

    def send_task(self, task: str) -> ModelTurn:
        self.messages.append({"role": "user", "content": task})
        return self._complete()

    def send_tool_results(self, results: list[ToolResult]) -> ModelTurn:
        self.messages.append(
            {
                "role": "user",
                "content": [
                    {
                        "type": "tool_result",
                        "tool_use_id": r.call_id,
                        "content": r.content,
                        "is_error": r.is_error,
                    }
                    for r in results
                ],
            }
        )
        return self._complete()

    def _complete(self) -> ModelTurn:
        response = self._adapter.create(
            system=self._system, messages=self.messages,
            # The LLM judge sends no tools; omit the key rather than send [].
            **({"tools": self._tools} if self._tools else {}),
            # Structured outputs; forced tool_choice is rejected on newer models.
            **({"output_config": {"format": {"type": "json_schema", "schema": self._schema}}}
               if self._schema else {}),
        )
        self.structured = self._schema is not None
        # Replay the full content (thinking blocks included) on later turns.
        self.messages.append({"role": "assistant", "content": response.content})
        return ModelTurn(
            text="".join(b.text for b in response.content if b.type == "text"),
            tool_calls=[
                ToolCallRequest(id=b.id, name=b.name, arguments=dict(b.input))
                for b in response.content
                if b.type == "tool_use"
            ],
            stop_reason=response.stop_reason,
            raw=response.to_dict(),
            usage=_usage(response),
        )


def _usage(response: Any) -> dict[str, int]:
    usage = getattr(response, "usage", None)
    return {k: v for k in USAGE_KEYS if isinstance(v := getattr(usage, k, None), int)}
