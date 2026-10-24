from lure.adapters.base import (
    AdapterError,
    Conversation,
    ModelAdapter,
    ModelTurn,
    ToolCallRequest,
    ToolResult,
    ToolSpec,
)

# Providers Lure has an adapter for.
TARGETS = ("ollama", "anthropic", "openai")

__all__ = [
    "TARGETS",
    "AdapterError",
    "Conversation",
    "ModelAdapter",
    "ModelTurn",
    "ToolCallRequest",
    "ToolResult",
    "ToolSpec",
]
