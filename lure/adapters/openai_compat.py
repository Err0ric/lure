"""OpenAI-compatible adapter, using the /chat/completions endpoint with
function tools.

Works with any server that speaks that API: OpenAI, vLLM, Groq, LM Studio,
llama.cpp's server and others. Only the base URL and model change; attacks
do not. Settings come from arguments, else the environment (loaded from
.env in the current directory if not already set):

  LURE_OPENAI_BASE_URL  default https://api.openai.com/v1
  LURE_OPENAI_API_KEY   falls back to OPENAI_API_KEY; optional for servers
                        that need no key (most local ones)
  LURE_OPENAI_MODEL     used when --model is not given

Talks only to the configured server.
"""

from __future__ import annotations

import json
import os
import time
from collections.abc import Callable
from typing import Any
from urllib.parse import urlsplit

import httpx2
from dotenv import find_dotenv, load_dotenv

from lure.adapters.base import (
    AdapterError,
    Conversation,
    ModelAdapter,
    ModelTurn,
    ToolCallRequest,
    ToolResult,
    ToolSpec,
)

DEFAULT_BASE_URL = "https://api.openai.com/v1"
# Statuses worth another try: rate limits and transient server errors.
RETRY_STATUSES = (408, 429, 500, 502, 503, 504)


class OpenAICompatAdapter(ModelAdapter):
    provider = "openai"

    def __init__(
        self,
        model: str | None = None,
        base_url: str | None = None,
        api_key: str | None = None,
        timeout: float = 300.0,
        max_retries: int = 2,
        transport: httpx2.BaseTransport | None = None,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        load_dotenv(find_dotenv(usecwd=True), override=False)
        model = model or os.environ.get("LURE_OPENAI_MODEL")
        if not model:
            raise AdapterError("no model for the OpenAI-compatible target: pass --model or set "
                               "LURE_OPENAI_MODEL in .env")
        super().__init__(model)
        self.base_url = (base_url or os.environ.get("LURE_OPENAI_BASE_URL")
                         or DEFAULT_BASE_URL).rstrip("/")
        parts = urlsplit(self.base_url)
        if parts.scheme not in ("http", "https") or not parts.netloc:
            raise AdapterError(f"LURE_OPENAI_BASE_URL must be an http(s) URL, got {self.base_url!r}")
        api_key = api_key or os.environ.get("LURE_OPENAI_API_KEY") or os.environ.get("OPENAI_API_KEY")
        if not api_key and parts.netloc == urlsplit(DEFAULT_BASE_URL).netloc:
            raise AdapterError("no OpenAI credentials: set LURE_OPENAI_API_KEY in .env")
        headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
        self.max_retries = max_retries
        self._sleep = sleep
        self._client = httpx2.Client(
            base_url=self.base_url, timeout=timeout, transport=transport, headers=headers
        )

    def start(self, system: str, tools: list[ToolSpec]) -> OpenAICompatConversation:
        return OpenAICompatConversation(self, system, tools)

    def chat(self, payload: dict[str, Any]) -> dict[str, Any]:
        for attempt in range(self.max_retries + 1):
            try:
                response = self._client.post("/chat/completions", json=payload)
            except httpx2.HTTPError as e:
                if attempt < self.max_retries:
                    self._sleep(2 ** attempt)
                    continue
                raise AdapterError(f"request to {self.base_url} failed: {e}") from e
            if response.status_code in RETRY_STATUSES and attempt < self.max_retries:
                self._sleep(2 ** attempt)
                continue
            break
        if response.status_code != 200:
            raise AdapterError(
                f"{self.base_url} returned HTTP {response.status_code}: {response.text[:500]}"
            )
        try:
            data = response.json()
        except ValueError as e:
            raise AdapterError(f"{self.base_url} returned invalid JSON: {e}") from e
        choices = data.get("choices") if isinstance(data, dict) else None
        if not choices or not isinstance(choices[0].get("message"), dict):
            raise AdapterError(f"response has no message: {str(data)[:500]}")
        return data


class OpenAICompatConversation(Conversation):
    def __init__(
        self, adapter: OpenAICompatAdapter, system: str, tools: list[ToolSpec]
    ) -> None:
        self._adapter = adapter
        self._tools = _function_tools(tools)
        self.messages: list[dict[str, Any]] = [{"role": "system", "content": system}]
        self._call_count = 0

    def send_task(self, task: str) -> ModelTurn:
        self.messages.append({"role": "user", "content": task})
        return self._complete()

    def set_tools(self, tools: list[ToolSpec]) -> None:
        self._tools = _function_tools(tools)

    def send_tool_results(self, results: list[ToolResult]) -> ModelTurn:
        for r in results:
            content = f"ERROR: {r.content}" if r.is_error else r.content
            self.messages.append({"role": "tool", "tool_call_id": r.call_id, "content": content})
        return self._complete()

    def _complete(self) -> ModelTurn:
        request: dict[str, Any] = {"model": self._adapter.model, "messages": self.messages}
        if self._tools:  # the LLM judge sends no tools
            request["tools"] = self._tools
        data = self._adapter.chat(request)
        choice = data["choices"][0]
        message = choice["message"]
        calls = [self._parse_call(c) for c in message.get("tool_calls") or []]
        # Replay only the standard fields: some servers reject extras such as
        # "refusal" or "reasoning_content" on the way back in.
        replay: dict[str, Any] = {"role": "assistant", "content": message.get("content")}
        if calls:
            replay["tool_calls"] = [
                {"id": c.id, "type": "function",
                 "function": {"name": c.name, "arguments": json.dumps(c.arguments)}}
                for c in calls
            ]
        self.messages.append(replay)
        return ModelTurn(
            text=message.get("content") or "",
            tool_calls=calls,
            stop_reason=choice.get("finish_reason"),
            raw=data,
            usage=_usage(data.get("usage")),
        )

    def _parse_call(self, call: dict[str, Any]) -> ToolCallRequest:
        # Not every server assigns call ids, so make stable ones.
        self._call_count += 1
        fn = call.get("function") or {}
        args = fn.get("arguments") or {}
        if isinstance(args, str):
            try:
                args = json.loads(args) if args.strip() else {}
            except json.JSONDecodeError as e:
                raise AdapterError(f"tool call arguments are not JSON: {args!r}") from e
        if not isinstance(args, dict):
            raise AdapterError(f"tool call arguments are not an object: {args!r}")
        return ToolCallRequest(
            id=call.get("id") or f"call_{self._call_count}",
            name=fn.get("name", ""),
            arguments=args,
        )


def _usage(usage: Any) -> dict[str, int]:
    """OpenAI's prompt/completion counts under Lure's names."""
    if not isinstance(usage, dict):
        return {}
    names = {"prompt_tokens": "input_tokens", "completion_tokens": "output_tokens"}
    return {ours: v for theirs, ours in names.items()
            if isinstance(v := usage.get(theirs), int)}


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
