import uuid
import re
from typing import Any
from sqlalchemy.ext.asyncio import AsyncSession

from app.agent_tools import execute_agent_tool
from app.llm.base import LLMProvider
from app.llm.factory import create_llm_provider


SYSTEM_PROMPT = """
You are TracePilot, a Linux network incident investigator.

You may investigate only through the provided read-only tools.

Rules:
1. Never claim that a destination or process is malicious unless the
   telemetry proves it.
2. Clearly separate observed facts from possible explanations.
3. Every factual finding must cite one or more event IDs returned by tools.
4. Use the citation format [event:UUID].
5. Never invent event IDs.
6. Mention missing or truncated evidence.
7. Do not provide commands that modify the host.
"""


TOOLS = [
    {
        "type": "function",
        "name": "get_process_connections",
        "description": (
            "Get TCP connection events for one PID between two timestamps."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "minimum": 1},
                "start_time": {
                    "type": "string",
                    "format": "date-time",
                },
                "end_time": {
                    "type": "string",
                    "format": "date-time",
                },
            },
            "required": ["pid", "start_time", "end_time"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "get_top_network_processes",
        "description": (
            "Find processes with the most connections in a recent window."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1440,
                },
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 100,
                },
            },
            "required": ["minutes", "limit"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "find_connection_bursts",
        "description": (
            "Find processes exceeding a connection threshold "
            "within one-minute windows."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "threshold": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 10000,
                },
                "minutes": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": 1440,
                },
            },
            "required": ["threshold", "minutes"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "find_unusual_destinations",
        "description": (
            "Find destinations a PID contacted recently that were "
            "not present during its preceding baseline period."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "minimum": 1},
            },
            "required": ["pid"],
            "additionalProperties": False,
        },
        "strict": True,
    },
    {
        "type": "function",
        "name": "get_event_timeline",
        "description": (
            "Get a chronological 24-hour network timeline for one PID."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "pid": {"type": "integer", "minimum": 1},
            },
            "required": ["pid"],
            "additionalProperties": False,
        },
        "strict": True,
    },
]

class EvidenceValidationError(RuntimeError):
    pass


def extract_tool_event_ids(value: Any) -> set[str]:
    event_ids = set()

    if isinstance(value, dict):
        for key, child in value.items():
            if key == "event_id" and isinstance(child, str):
                event_ids.add(child)

            elif key == "event_ids" and isinstance(child, list):
                event_ids.update(
                    item
                    for item in child
                    if isinstance(item, str)
                )

            else:
                event_ids.update(
                    extract_tool_event_ids(child)
                )

    elif isinstance(value, list):
        for child in value:
            event_ids.update(
                extract_tool_event_ids(child)
            )

    return event_ids


def validate_report_evidence(
    report: str,
    allowed_event_ids: set[str],
) -> None:
    cited_event_ids = set(
        re.findall(
            r"\[event:([0-9a-fA-F-]{36})\]",
            report,
        )
    )

    invented_event_ids = (
        cited_event_ids - allowed_event_ids
    )

    if invented_event_ids:
        raise EvidenceValidationError(
            "Report cited event IDs that were not "
            f"returned by tools: "
            f"{sorted(invented_event_ids)}"
        )

    if allowed_event_ids and not cited_event_ids:
        raise EvidenceValidationError(
            "Report used event evidence without citing "
            "any returned event IDs."
        )

async def run_investigation_agent(
    question: str,
    investigation_id: uuid.UUID,
    session: AsyncSession,
    provider: LLMProvider | None = None,
) -> str:
    if provider is None:
        provider = create_llm_provider()

    response = await provider.start(
        question=question,
        tools=TOOLS,
        instructions=SYSTEM_PROMPT,
    )

    allowed_event_ids: set[str] = set()

    maximum_rounds = 8

    for _ in range(maximum_rounds):
        if not response.tool_requests:
            if not response.text:
                raise RuntimeError(
                    "Provider returned no investigation report."
                )

            validate_report_evidence(
                response.text,
                allowed_event_ids,
            )

            return response.text

        tool_results = []

        for request in response.tool_requests:
            result = await execute_agent_tool(
                tool_name=request.name,
                raw_arguments=request.arguments,
                investigation_id=investigation_id,
                session=session,
            )
            
            allowed_event_ids.update(
                extract_tool_event_ids(result)
            )

            tool_results.append(
                {
                    "call_id": request.call_id,
                    "tool_name": request.name,
                    "result": result,
                }
            )

        response = (
            await provider.continue_with_tool_results(
                state=response.state,
                tool_results=tool_results,
                tools=TOOLS,
                instructions=SYSTEM_PROMPT,
            )
        )

    raise RuntimeError(
        "Agent exceeded the maximum number of tool rounds."
    )
