import uuid

import pytest
from sqlalchemy import select

from app.models import AgentToolCall, Investigation


@pytest.mark.asyncio
async def test_create_and_retrieve_investigation(
    client,
    monkeypatch,
):
    async def fake_agent(
        question,
        investigation_id,
        session,
        provider=None,
    ):
        assert question == "Investigate PID 1234"
        assert isinstance(investigation_id, uuid.UUID)

        return (
            "PID 1234 had supported network activity."
        )

    monkeypatch.setattr(
        "app.main.run_investigation_agent",
        fake_agent,
    )

    create_response = await client.post(
        "/investigations",
        json={
            "question": "Investigate PID 1234",
        },
    )

    assert create_response.status_code == 201

    created = create_response.json()

    assert created["status"] == "completed"
    assert created["answer"] == (
        "PID 1234 had supported network activity."
    )
    assert created["completed_at"] is not None

    get_response = await client.get(
        f"/investigations/{created['id']}"
    )

    assert get_response.status_code == 200
    assert get_response.json() == created


@pytest.mark.asyncio
async def test_failed_agent_marks_investigation_failed(
    client,
    test_session,
    monkeypatch,
):
    async def failing_agent(
        question,
        investigation_id,
        session,
        provider=None,
    ):
        raise RuntimeError("Mock provider failure")

    monkeypatch.setattr(
        "app.main.run_investigation_agent",
        failing_agent,
    )

    response = await client.post(
        "/investigations",
        json={
            "question": "Investigate failed process",
        },
    )

    assert response.status_code == 502
    assert response.json()["detail"] == (
        "Investigation agent failed."
    )

    result = await test_session.execute(
        select(Investigation).where(
            Investigation.question
            == "Investigate failed process"
        )
    )

    investigation = result.scalar_one()

    assert investigation.status == "failed"
    assert investigation.answer == (
        "The investigation could not be completed."
    )
    assert investigation.completed_at is not None


@pytest.mark.asyncio
async def test_tool_call_audit_endpoint(
    client,
    test_session,
    monkeypatch,
):
    async def fake_agent(
        question,
        investigation_id,
        session,
        provider=None,
    ):
        return "No unsupported conclusion was made."

    monkeypatch.setattr(
        "app.main.run_investigation_agent",
        fake_agent,
    )

    create_response = await client.post(
        "/investigations",
        json={
            "question": "Investigate PID 5678",
        },
    )

    assert create_response.status_code == 201

    investigation_id = uuid.UUID(
        create_response.json()["id"]
    )

    tool_call = AgentToolCall(
        investigation_id=investigation_id,
        tool_name="get_event_timeline",
        arguments={"pid": 5678},
        result={
            "pid": 5678,
            "timeline": [],
        },
    )

    test_session.add(tool_call)
    await test_session.commit()

    response = await client.get(
        f"/investigations/{investigation_id}/tool-calls"
    )

    assert response.status_code == 200

    calls = response.json()

    assert len(calls) == 1
    assert calls[0]["tool_name"] == (
        "get_event_timeline"
    )
    assert calls[0]["arguments"] == {"pid": 5678}
    assert calls[0]["result"] == {
        "pid": 5678,
        "timeline": [],
    }
