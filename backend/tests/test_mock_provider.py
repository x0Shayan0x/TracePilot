import pytest

from app.llm.mock_provider import (
    MockProvider,
    extract_event_ids,
)


def test_extract_event_ids_from_nested_results():
    result = {
        "events": [
            {"event_id": "event-1"},
            {"event_id": "event-2"},
        ],
        "bursts": [
            {
                "event_ids": [
                    "event-2",
                    "event-3",
                ]
            }
        ],
    }

    assert extract_event_ids(result) == [
        "event-1",
        "event-2",
        "event-3",
    ]


@pytest.mark.asyncio
async def test_mock_provider_requires_pid():
    provider = MockProvider()

    response = await provider.start(
        question="Why were there so many connections?",
        tools=[],
        instructions="Test instructions",
    )

    assert response.tool_requests == []
    assert response.text is not None
    assert "requires the question to include a PID" in response.text


@pytest.mark.asyncio
async def test_mock_provider_requests_only_expected_tools():
    provider = MockProvider()

    response = await provider.start(
        question="Investigate PID 1234",
        tools=[],
        instructions="Test instructions",
    )

    assert response.text is None
    assert response.state == {"pid": 1234}

    tool_names = {
        request.name
        for request in response.tool_requests
    }

    assert tool_names == {
        "get_event_timeline",
        "find_connection_bursts",
        "find_unusual_destinations",
    }

    for request in response.tool_requests:
        if request.name in {
            "get_event_timeline",
            "find_unusual_destinations",
        }:
            assert request.arguments == {"pid": 1234}


@pytest.mark.asyncio
async def test_mock_report_cites_returned_event_ids():
    provider = MockProvider()

    response = await provider.continue_with_tool_results(
        state={"pid": 1234},
        tool_results=[
            {
                "call_id": "mock-timeline",
                "tool_name": "get_event_timeline",
                "result": {
                    "events": [
                        {"event_id": "event-abc"},
                        {"event_id": "event-def"},
                    ]
                },
            }
        ],
        tools=[],
        instructions="Test instructions",
    )

    assert response.tool_requests == []
    assert "[event:event-abc]" in response.text
    assert "[event:event-def]" in response.text


@pytest.mark.asyncio
async def test_mock_provider_does_not_invent_findings_without_events():
    provider = MockProvider()

    response = await provider.continue_with_tool_results(
        state={"pid": 1234},
        tool_results=[
            {
                "call_id": "mock-timeline",
                "tool_name": "get_event_timeline",
                "result": {"events": []},
            }
        ],
        tools=[],
        instructions="Test instructions",
    )

    assert response.tool_requests == []
    assert "No supporting connection events" in response.text
    assert "[event:" not in response.text
    assert "malicious" not in response.text.lower()
