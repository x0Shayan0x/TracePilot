from datetime import datetime, timezone

import pytest
from sqlalchemy import select

from app.models import ConnectionEvent


@pytest.mark.asyncio
async def test_connection_event_can_be_saved(
    test_session,
):
    event = ConnectionEvent(
        timestamp=datetime.now(timezone.utc),
        pid=1234,
        process_name="python",
        uid=1000,
        destination_ip="8.8.8.8",
        destination_port=443,
        ip_version=4,
        duration_ms=12.5,
        source="test",
    )

    test_session.add(event)
    await test_session.commit()

    result = await test_session.execute(
        select(ConnectionEvent).where(
            ConnectionEvent.id == event.id
        )
    )

    saved_event = result.scalar_one()

    assert saved_event.pid == 1234
    assert saved_event.process_name == "python"
    assert str(saved_event.destination_ip) == "8.8.8.8"
    assert saved_event.destination_port == 443
    assert saved_event.source == "test"
