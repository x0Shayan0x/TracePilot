import os
from typing import Any
from uuid import uuid4

from google import genai
from google.genai import types

from app.llm.base import (
    LLMProvider,
    ProviderResponse,
    ToolRequest,
)


class GeminiProvider(LLMProvider):
    def __init__(self):
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise RuntimeError(
                "GEMINI_API_KEY is required when "
                "LLM_PROVIDER=gemini."
            )

        self.client = genai.Client(api_key=api_key)
        self.model = os.getenv(
            "GEMINI_MODEL",
            "gemini-2.5-flash",
        )

    def _convert_tools(
        self,
        tools: list[dict],
    ) -> list[types.Tool]:
        """
        Convert OpenAI Responses API tool definitions into
        Gemini function declarations.
        """
        declarations = []

        for tool in tools:
            if tool.get("type") != "function":
                continue

            # Support both:
            # {"type": "function", "name": ..., ...}
            #
            # and:
            # {"type": "function", "function": {...}}
            function = tool.get("function", tool)

            declarations.append(
                types.FunctionDeclaration(
                    name=function["name"],
                    description=function.get(
                        "description",
                        "",
                    ),
                    parameters_json_schema=function.get(
                        "parameters",
                        {
                            "type": "object",
                            "properties": {},
                        },
                    ),
                )
            )

        if not declarations:
            return []

        return [
            types.Tool(
                function_declarations=declarations,
            )
        ]

    def _build_config(
        self,
        tools: list[dict],
        instructions: str,
    ) -> types.GenerateContentConfig:
        return types.GenerateContentConfig(
            system_instruction=instructions,
            tools=self._convert_tools(tools),
            automatic_function_calling=(
                types.AutomaticFunctionCallingConfig(
                    disable=True,
                )
            ),
        )

    def _convert_response(
        self,
        response,
        contents: list[types.Content],
    ) -> ProviderResponse:
        tool_requests = []
        text_parts = []
        pending_calls = {}

        if not response.candidates:
            return ProviderResponse(
                text=None,
                tool_requests=[],
                state={
                    "contents": contents,
                    "pending_calls": {},
                },
            )

        model_content = response.candidates[0].content

        if model_content is not None:
            for part in model_content.parts or []:
                if part.text:
                    text_parts.append(part.text)

                if part.function_call:
                    function_call = part.function_call

                    call_id = (
                        function_call.id
                        or str(uuid4())
                    )

                    arguments = dict(
                        function_call.args or {}
                    )

                    tool_requests.append(
                        ToolRequest(
                            call_id=call_id,
                            name=function_call.name,
                            arguments=arguments,
                        )
                    )

                    pending_calls[call_id] = (
                        function_call.name
                    )

            updated_contents = [
                *contents,
                model_content,
            ]
        else:
            updated_contents = list(contents)

        text = "\n".join(text_parts).strip()

        return ProviderResponse(
            text=text or None,
            tool_requests=tool_requests,
            state={
                "contents": updated_contents,
                "pending_calls": pending_calls,
            },
        )

    async def start(
        self,
        question: str,
        tools: list[dict],
        instructions: str,
    ) -> ProviderResponse:
        contents = [
            types.Content(
                role="user",
                parts=[
                    types.Part.from_text(
                        text=question,
                    )
                ],
            )
        ]

        response = (
            await self.client.aio.models.generate_content(
                model=self.model,
                contents=contents,
                config=self._build_config(
                    tools,
                    instructions,
                ),
            )
        )

        return self._convert_response(
            response,
            contents,
        )

    async def continue_with_tool_results(
        self,
        state: Any,
        tool_results: list[dict],
        tools: list[dict],
        instructions: str,
    ) -> ProviderResponse:
        contents = list(state["contents"])
        pending_calls = state.get(
            "pending_calls",
            {},
        )

        response_parts = []

        for tool_result in tool_results:
            call_id = tool_result["call_id"]
            tool_name = pending_calls.get(call_id)

            if not tool_name:
                raise RuntimeError(
                    f"Unknown Gemini tool call ID: "
                    f"{call_id}"
                )

            result = tool_result["result"]

            # Gemini requires the function response to
            # contain a JSON object.
            if not isinstance(result, dict):
                result = {"data": result}

            response_parts.append(
                types.Part.from_function_response(
                    name=tool_name,
                    response=result,
                )
            )

        contents.append(
            types.Content(
                role="user",
                parts=response_parts,
            )
        )

        response = (
            await self.client.aio.models.generate_content(
                model=self.model,
                contents=contents,
                config=self._build_config(
                    tools,
                    instructions,
                ),
            )
        )

        return self._convert_response(
            response,
            contents,
        )
