from datetime import datetime, timedelta, timezone

import pytest

from app.agent_tools import (
    ConnectionBurstsArguments,
    UnusualDestinationsArguments,
    find_connection_bursts,
    find_unusual_destinations,
)
from app.main import find_high_unique_destinations
from app.models import ConnectionEvent


async def add_event(
    session,
    *,
    timestamp,
    pid=1234,
    process_name="python",
    destination_ip="8.8.8.8",
    destination_port=443,
):
    event = ConnectionEvent(
        timestamp=timestamp,
        pid=pid,
        process_name=process_name,
        uid=1000,
        destination_ip=destination_ip,
        destination_port=destination_port,
        ip_version=4,
        duration_ms=10.0,
        source="test",
    )

    session.add(event)
    await session.flush()

    return event


@pytest.mark.asyncio
async def test_detects_connection_burst(
    test_session,
):
    now = datetime.now(timezone.utc).replace(
        second=10,
        microsecond=0,
    )

    events = []

    # Four connections in the same minute exceed
    # a threshold of three.
    for index in range(4):
        events.append(
            await add_event(
                test_session,
                timestamp=now + timedelta(
                    seconds=index
                ),
            )
        )

    await test_session.commit()

    result = await find_connection_bursts(
        session=test_session,
        arguments=ConnectionBurstsArguments(
            threshold=3,
            minutes=60,
        ),
    )

    assert len(result["bursts"]) == 1

    burst = result["bursts"][0]

    assert burst["pid"] == 1234
    assert burst["connection_count"] == 4
    assert set(burst["event_ids"]) == {
        str(event.id)
        for event in events
    }


@pytest.mark.asyncio
async def test_detects_destination_absent_from_baseline(
    test_session,
):
    now = datetime.now(timezone.utc)

    # Known destination from the preceding baseline.
    await add_event(
        test_session,
        timestamp=now - timedelta(hours=2),
        destination_ip="8.8.8.8",
        destination_port=443,
    )

    # Known destination contacted again recently.
    await add_event(
        test_session,
        timestamp=now - timedelta(minutes=10),
        destination_ip="8.8.8.8",
        destination_port=443,
    )

    # Newly observed destination.
    new_event = await add_event(
        test_session,
        timestamp=now - timedelta(minutes=5),
        destination_ip="203.0.113.20",
        destination_port=8443,
    )

    await test_session.commit()

    result = await find_unusual_destinations(
        session=test_session,
        arguments=UnusualDestinationsArguments(
            pid=1234
        ),
    )

    unusual = result["unusual_destinations"]

    assert len(unusual) == 1
    assert unusual[0]["destination_ip"] == (
        "203.0.113.20"
    )
    assert unusual[0]["destination_port"] == 8443
    assert unusual[0]["event_ids"] == [
        str(new_event.id)
    ]


@pytest.mark.asyncio
async def test_detects_high_unique_destination_count(
    test_session,
):
    now = datetime.now(timezone.utc)

    events = []

    for index, destination_ip in enumerate(
        [
            "203.0.113.10",
            "203.0.113.11",
            "203.0.113.12",
        ]
    ):
        events.append(
            await add_event(
                test_session,
                timestamp=now - timedelta(
                    minutes=index
                ),
                destination_ip=destination_ip,
                destination_port=443,
            )
        )

    await test_session.commit()

    result = await find_high_unique_destinations(
        threshold=2,
        minutes=60,
        session=test_session,
    )

    assert len(result) == 1

    finding = result[0]

    assert finding.pid == 1234
    assert finding.process_name == "python"
    assert finding.unique_destination_count == 3
    assert finding.connection_count == 3
    assert set(finding.event_ids) == {
        event.id
        for event in events
    }
