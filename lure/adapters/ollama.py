"""Ollama adapter, using the /api/chat endpoint with tool calling.

Talks only to the configured Ollama server (local by default).
"""

from __future__ import annotations

import json
from typing import Any

import httpx2

from lure.adapters.base import (
    AdapterError,
    Conversation,
    ModelAdapter,
    ModelTurn,
    ToolCallRequest,
    ToolResult,
    ToolSpec,
)

DEFAULT_BASE_URL = "http://localhost:11434"
DEFAULT_MODEL = "llama3.1:8b"


class OllamaAdapter(ModelAdapter):
    provider = "ollama"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 300.0,
        transport: httpx2.BaseTransport | None = None,
    ) -> None:
        super().__init__(model)
        self.base_url = base_url
        self._client = httpx2.Client(
            base_url=base_url, timeout=timeout, transport=transport
        )

    def start(self, system: str, tools: list[ToolSpec]) -> OllamaConversation:
        return OllamaConversation(self, system, tools)

    def chat(self, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post("/api/chat", json=payload)
        except httpx2.HTTPError as e:
            raise AdapterError(f"ollama request to {self.base_url} failed: {e}") from e
        if response.status_code != 200:
            raise AdapterError(
                f"ollama returned HTTP {response.status_code}: {response.text[:500]}"
            )
        try:
            data = response.json()
        except ValueError as e:
            raise AdapterError(f"ollama returned invalid JSON: {e}") from e
        if not isinstance(data.get("message"), dict):
            raise AdapterError(f"ollama response has no message: {str(data)[:500]}")
        return data


class OllamaConversation(Conversation):
    def __init__(
        self, adapter: OllamaAdapter, system: str, tools: list[ToolSpec]
    ) -> None:
        self._adapter = adapter
        self._tools = _function_tools(tools)
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        self._call_count = 0
        self._schema: dict[str, Any] | None = None

    def send_task(self, task: str) -> ModelTurn:
        self.messages.append({"role": "user", "content": task})
        return self._complete()

    def set_tools(self, tools: list[ToolSpec]) -> None:
        self._tools = _function_tools(tools)

    def set_output_schema(self, schema: dict[str, Any]) -> None:
        self._schema = schema

    def send_tool_results(self, results: list[ToolResult]) -> ModelTurn:
        for r in results:
            content = f"ERROR: {r.content}" if r.is_error else r.content
            self.messages.append(
                {"role": "tool", "content": content, "tool_name": r.name}
            )
        return self._complete()

    def _complete(self) -> ModelTurn:
        request = {"model": self._adapter.model, "messages": self.messages, "stream": False}
        if self._tools:  # the LLM judge sends no tools
            request["tools"] = self._tools
        if self._schema:
            request["format"] = self._schema
        data = self._adapter.chat(request)
        self.structured = self._schema is not None
        message = data["message"]
        self.messages.append(message)
        return ModelTurn(
            text=message.get("content") or "",
            tool_calls=[self._parse_call(c) for c in message.get("tool_calls") or []],
            stop_reason=data.get("done_reason"),
            raw=data,
            usage=_usage(data),
        )

    def _parse_call(self, call: dict[str, Any]) -> ToolCallRequest:
        # Ollama does not always assign call ids, so make stable ones.
        self._call_count += 1
        fn = call.get("function") or {}
        args = fn.get("arguments") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args)
            except json.JSONDecodeError as e:
                raise AdapterError(f"tool call arguments are not JSON: {args!r}") from e
        return ToolCallRequest(
            id=call.get("id") or f"call_{self._call_count}",
            name=fn.get("name", ""),
            arguments=args,
        )


def _usage(data: dict[str, Any]) -> dict[str, int]:
    """Ollama's prompt_eval_count and eval_count, as input and output tokens.
    A count Ollama leaves out (for example a fully cached prompt) is left out."""
    counts = {"input_tokens": data.get("prompt_eval_count"), "output_tokens": data.get("eval_count")}
    return {k: v for k, v in counts.items() if isinstance(v, int) and not isinstance(v, bool)}


def _function_tools(tools: list[ToolSpec]) -> list[dict[str, Any]]:
    return [
        {
            "type": "function",
            "function": {
                "name": t.name,
                "description": t.description,
                "parameters": t.parameters,
            },
        }
        for t in tools
    ]
