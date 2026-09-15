import uuid

import pytest
from pydantic import ValidationError

from app.agent_tools import (
    EventTimelineArguments,
    TOOL_REGISTRY,
    ToolNotAllowedError,
    execute_agent_tool,
)


class FakeSession:
    def __init__(self):
        self.added = []
        self.commit_count = 0

    def add(self, record):
        self.added.append(record)

    async def commit(self):
        self.commit_count += 1


@pytest.mark.asyncio
async def test_unknown_tool_is_rejected_and_audited():
    session = FakeSession()
    investigation_id = uuid.uuid4()

    with pytest.raises(
        ToolNotAllowedError,
        match="not permitted",
    ):
        await execute_agent_tool(
            tool_name="run_shell_command",
            raw_arguments={"command": "whoami"},
            investigation_id=investigation_id,
            session=session,
        )

    assert session.commit_count == 1
    assert len(session.added) == 1

    audit_record = session.added[0]

    assert audit_record.investigation_id == investigation_id
    assert audit_record.tool_name == "run_shell_command"
    assert audit_record.arguments == {
        "command": "whoami",
    }
    assert audit_record.result["error"] == "tool_not_allowed"


@pytest.mark.asyncio
async def test_invalid_arguments_are_rejected_and_audited():
    session = FakeSession()
    investigation_id = uuid.uuid4()

    with pytest.raises(ValidationError):
        await execute_agent_tool(
            tool_name="get_event_timeline",
            raw_arguments={"pid": 0},
            investigation_id=investigation_id,
            session=session,
        )

    assert session.commit_count == 1
    assert len(session.added) == 1

    audit_record = session.added[0]

    assert audit_record.tool_name == "get_event_timeline"
    assert audit_record.arguments == {"pid": 0}
    assert audit_record.result["error"] == "invalid_arguments"
    assert audit_record.result["details"]


@pytest.mark.asyncio
async def test_approved_tool_executes_and_is_audited(
    monkeypatch,
):
    session = FakeSession()
    investigation_id = uuid.uuid4()

    async def fake_timeline_tool(
        session,
        arguments,
    ):
        assert arguments.pid == 1234

        return {
            "pid": arguments.pid,
            "timeline": [],
            "event_ids": [
                "11111111-1111-4111-8111-111111111111"
            ],
        }

    monkeypatch.setitem(
        TOOL_REGISTRY,
        "get_event_timeline",
        {
            "arguments_model": EventTimelineArguments,
            "function": fake_timeline_tool,
        },
    )

    result = await execute_agent_tool(
        tool_name="get_event_timeline",
        raw_arguments={"pid": 1234},
        investigation_id=investigation_id,
        session=session,
    )

    assert result["pid"] == 1234
    assert session.commit_count == 1
    assert len(session.added) == 1

    audit_record = session.added[0]

    assert audit_record.investigation_id == investigation_id
    assert audit_record.tool_name == "get_event_timeline"
    assert audit_record.arguments == {"pid": 1234}
    assert audit_record.result == result
