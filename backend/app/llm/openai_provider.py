import json
import os
from typing import Any

from openai import AsyncOpenAI

from app.llm.base import (
    LLMProvider,
    ProviderResponse,
    ToolRequest,
)


class OpenAIProvider(LLMProvider):
    def __init__(self):
        api_key = os.getenv("OPENAI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "OPENAI_API_KEY is required when "
                "LLM_PROVIDER=openai."
            )

        self.client = AsyncOpenAI(api_key=api_key)
        self.model = os.getenv(
            "OPENAI_MODEL",
            "gpt-5.6",
        )

    def _convert_response(
        self,
        response,
        input_items: list,
    ) -> ProviderResponse:
        tool_requests = []

        for item in response.output:
            if item.type == "function_call":
                tool_requests.append(
                    ToolRequest(
                        call_id=item.call_id,
                        name=item.name,
                        arguments=json.loads(
                            item.arguments
                        ),
                    )
                )

        return ProviderResponse(
            text=response.output_text or None,
            tool_requests=tool_requests,
            state={
                "input_items": (
                    input_items + list(response.output)
                )
            },
        )

    async def start(
        self,
        question: str,
        tools: list[dict],
        instructions: str,
    ) -> ProviderResponse:
        input_items = [
            {
                "role": "user",
                "content": question,
            }
        ]

        response = await self.client.responses.create(
            model=self.model,
            instructions=instructions,
            tools=tools,
            input=input_items,
        )

        return self._convert_response(
            response,
            input_items,
        )

    async def continue_with_tool_results(
        self,
        state: Any,
        tool_results: list[dict],
        tools: list[dict],
        instructions: str,
    ) -> ProviderResponse:
        input_items = list(state["input_items"])

        for tool_result in tool_results:
            input_items.append(
                {
                    "type": "function_call_output",
                    "call_id": tool_result["call_id"],
                    "output": json.dumps(
                        tool_result["result"]
                    ),
                }
            )

        response = await self.client.responses.create(
            model=self.model,
            instructions=instructions,
            tools=tools,
            input=input_items,
        )

        return self._convert_response(
            response,
            input_items,
        )
