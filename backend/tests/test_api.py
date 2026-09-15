from datetime import datetime, timezone

import pytest


def event_payload(
    *,
    pid=1234,
    process_name="python",
    destination_ip="8.8.8.8",
    destination_port=443,
):
    return {
        "timestamp": (
            datetime.now(timezone.utc).isoformat()
        ),
        "pid": pid,
        "process_name": process_name,
        "uid": 1000,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "ip_version": 4,
        "duration_ms": 15.5,
        "source": "test",
    }


@pytest.mark.asyncio
async def test_create_and_query_connection(
    client,
):
    create_response = await client.post(
        "/events",
        json=event_payload(),
    )

    assert create_response.status_code == 201

    created = create_response.json()

    assert created["pid"] == 1234
    assert created["process_name"] == "python"
    assert created["destination_ip"] == "8.8.8.8"
    assert created["destination_port"] == 443
    assert created["id"]

    query_response = await client.get(
        "/processes/1234/connections"
    )

    assert query_response.status_code == 200

    connections = query_response.json()

    assert len(connections) == 1
    assert connections[0]["id"] == created["id"]


@pytest.mark.asyncio
async def test_invalid_event_is_rejected(
    client,
):
    payload = event_payload()
    payload["destination_port"] = 70000

    response = await client.post(
        "/events",
        json=payload,
    )

    assert response.status_code == 422


@pytest.mark.asyncio
async def test_top_processes_endpoint(
    client,
):
    for _ in range(3):
        response = await client.post(
            "/events",
            json=event_payload(
                pid=1234,
                process_name="python",
            ),
        )

        assert response.status_code == 201

    response = await client.post(
        "/events",
        json=event_payload(
            pid=5678,
            process_name="curl",
        ),
    )

    assert response.status_code == 201

    analytics_response = await client.get(
        "/analytics/top-processes",
        params={
            "minutes": 60,
            "limit": 10,
        },
    )

    assert analytics_response.status_code == 200

    processes = analytics_response.json()

    assert processes[0] == {
        "pid": 1234,
        "process_name": "python",
        "connection_count": 3,
    }

    assert processes[1] == {
        "pid": 5678,
        "process_name": "curl",
        "connection_count": 1,
    }
