from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass
class ToolRequest:
    call_id: str
    name: str
    arguments: dict[str, Any]


@dataclass
class ProviderResponse:
    text: str | None
    tool_requests: list[ToolRequest]
    state: Any = None


class LLMProvider(ABC):
    @abstractmethod
    async def start(
        self,
        question: str,
        tools: list[dict],
        instructions: str,
    ) -> ProviderResponse:
        pass

    @abstractmethod
    async def continue_with_tool_results(
        self,
        state: Any,
        tool_results: list[dict],
        tools: list[dict],
        instructions: str,
    ) -> ProviderResponse:
        pass
