import uuid

import pytest

from app.agent import (
    EvidenceValidationError,
    run_investigation_agent,
)
from app.llm.base import (
    LLMProvider,
    ProviderResponse,
    ToolRequest,
)


REAL_EVENT_ID = (
    "11111111-1111-4111-8111-111111111111"
)

INVENTED_EVENT_ID = (
    "99999999-9999-4999-8999-999999999999"
)


class EvidenceBackedProvider(LLMProvider):
    async def start(
        self,
        question,
        tools,
        instructions,
    ):
        assert question == "Investigate PID 1234"
        assert tools
        assert "Never invent event IDs" in instructions

        return ProviderResponse(
            text=None,
            tool_requests=[
                ToolRequest(
                    call_id="call-1",
                    name="get_event_timeline",
                    arguments={"pid": 1234},
                )
            ],
            state={"round": 1},
        )

    async def continue_with_tool_results(
        self,
        state,
        tool_results,
        tools,
        instructions,
    ):
        assert state == {"round": 1}
        assert tool_results[0]["call_id"] == "call-1"
        assert tool_results[0]["result"]["event_ids"] == [
            REAL_EVENT_ID
        ]

        return ProviderResponse(
            text=(
                "PID 1234 opened an outbound connection "
                f"[event:{REAL_EVENT_ID}]."
            ),
            tool_requests=[],
            state=state,
        )


class InventedEvidenceProvider(LLMProvider):
    async def start(
        self,
        question,
        tools,
        instructions,
    ):
        return ProviderResponse(
            text=None,
            tool_requests=[
                ToolRequest(
                    call_id="call-1",
                    name="get_event_timeline",
                    arguments={"pid": 1234},
                )
            ],
            state={},
        )

    async def continue_with_tool_results(
        self,
        state,
        tool_results,
        tools,
        instructions,
    ):
        return ProviderResponse(
            text=(
                "Unsupported finding "
                f"[event:{INVENTED_EVENT_ID}]."
            ),
            tool_requests=[],
            state=state,
        )


@pytest.mark.asyncio
async def test_agent_completes_evidence_backed_report(
    monkeypatch,
):
    executed_tools = []

    async def fake_execute_agent_tool(
        tool_name,
        raw_arguments,
        investigation_id,
        session,
    ):
        executed_tools.append(
            {
                "tool_name": tool_name,
                "arguments": raw_arguments,
            }
        )

        return {
            "pid": 1234,
            "event_ids": [REAL_EVENT_ID],
        }

    monkeypatch.setattr(
        "app.agent.execute_agent_tool",
        fake_execute_agent_tool,
    )

    answer = await run_investigation_agent(
        question="Investigate PID 1234",
        investigation_id=uuid.uuid4(),
        session=object(),
        provider=EvidenceBackedProvider(),
    )

    assert executed_tools == [
        {
            "tool_name": "get_event_timeline",
            "arguments": {"pid": 1234},
        }
    ]

    assert f"[event:{REAL_EVENT_ID}]" in answer


@pytest.mark.asyncio
async def test_agent_rejects_provider_inventing_evidence(
    monkeypatch,
):
    async def fake_execute_agent_tool(
        tool_name,
        raw_arguments,
        investigation_id,
        session,
    ):
        return {
            "pid": 1234,
            "event_ids": [REAL_EVENT_ID],
        }

    monkeypatch.setattr(
        "app.agent.execute_agent_tool",
        fake_execute_agent_tool,
    )

    with pytest.raises(
        EvidenceValidationError,
        match="not returned by tools",
    ):
        await run_investigation_agent(
            question="Investigate PID 1234",
            investigation_id=uuid.uuid4(),
            session=object(),
            provider=InventedEvidenceProvider(),
        )
