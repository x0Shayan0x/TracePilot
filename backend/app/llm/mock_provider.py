import re
from typing import Any

from app.llm.base import (
    LLMProvider,
    ProviderResponse,
    ToolRequest,
)


def extract_event_ids(value: Any) -> list[str]:
    event_ids = []

    if isinstance(value, dict):
        for key, child in value.items():
            if key == "event_id" and isinstance(child, str):
                event_ids.append(child)

            elif key == "event_ids" and isinstance(child, list):
                event_ids.extend(
                    item
                    for item in child
                    if isinstance(item, str)
                )

            else:
                event_ids.extend(
                    extract_event_ids(child)
                )

    elif isinstance(value, list):
        for item in value:
            event_ids.extend(extract_event_ids(item))

    # Remove duplicates while preserving order.
    return list(dict.fromkeys(event_ids))


class MockProvider(LLMProvider):
    async def start(
        self,
        question: str,
        tools: list[dict],
        instructions: str,
    ) -> ProviderResponse:
        match = re.search(
            r"\bPID\s*[:#]?\s*(\d+)\b",
            question,
            flags=re.IGNORECASE,
        )

        if match is None:
            return ProviderResponse(
                text=(
                    "Demo mode requires the question to "
                    "include a PID."
                ),
                tool_requests=[],
            )

        pid = int(match.group(1))

        return ProviderResponse(
            text=None,
            tool_requests=[
                ToolRequest(
                    call_id="mock-timeline",
                    name="get_event_timeline",
                    arguments={"pid": pid},
                ),
                ToolRequest(
                    call_id="mock-bursts",
                    name="find_connection_bursts",
                    arguments={
                        "threshold": 100,
                        "minutes": 1440,
                    },
                ),
                ToolRequest(
                    call_id="mock-unusual",
                    name="find_unusual_destinations",
                    arguments={"pid": pid},
                ),
            ],
            state={"pid": pid},
        )

    async def continue_with_tool_results(
        self,
        state: Any,
        tool_results: list[dict],
        tools: list[dict],
        instructions: str,
    ) -> ProviderResponse:
        event_ids = []

        for tool_result in tool_results:
            event_ids.extend(
                extract_event_ids(
                    tool_result["result"]
                )
            )

        event_ids = list(dict.fromkeys(event_ids))
        pid = state["pid"]

        if not event_ids:
            report = (
                f"No supporting connection events were "
                f"found for PID {pid}. No conclusion can "
                f"be made from the available telemetry."
            )

        else:
            citations = " ".join(
                f"[event:{event_id}]"
                for event_id in event_ids[:3]
            )

            report = (
                f"PID {pid} produced network activity "
                f"identified by TracePilot's deterministic "
                f"investigation tools. {citations}\n\n"
                f"This demo report does not determine that "
                f"the process was malicious. Application "
                f"logs and process context would be required "
                f"to establish the underlying cause."
            )

        return ProviderResponse(
            text=report,
            tool_requests=[],
            state=state,
        )
