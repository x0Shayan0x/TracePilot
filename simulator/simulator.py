import os
import time
from datetime import datetime, timedelta, timezone

import httpx


API_URL = os.getenv("API_URL", "http://api:8000")
SIMULATED_PID = 4242


def make_event(
    timestamp: datetime,
    destination_ip: str,
    destination_port: int = 443,
) -> dict:
    return {
        "timestamp": timestamp.isoformat(),
        "pid": SIMULATED_PID,
        "process_name": "python3",
        "uid": 1000,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "ip_version": 4,
        "duration_ms": 10.0,
        "source": "simulator",
    }


def wait_for_api() -> None:
    while True:
        try:
            response = httpx.get(
                f"{API_URL}/health",
                timeout=5,
            )

            if response.status_code == 200:
                print("TracePilot API is ready.")
                return

        except httpx.RequestError:
            pass

        print("Waiting for TracePilot API...")
        time.sleep(2)


def generate_events() -> list[dict]:
    now = datetime.now(timezone.utc)

    # Events from before the recent investigation window.
    baseline_time = now - timedelta(hours=2)

    baseline_events = [
        make_event(
            timestamp=baseline_time + timedelta(seconds=i),
            destination_ip="198.51.100.10",
            destination_port=443,
        )
        for i in range(10)
    ]

    # Keep every burst event inside the same minute.
    burst_start = now.replace(second=0, microsecond=0)

    burst_events = []

    for i in range(120):
        if i < 90:
            # Most connections target one new destination.
            destination_ip = "203.0.113.50"
        else:
            # The remaining connections spread across new destinations.
            destination_ip = f"203.0.113.{100 + (i - 90)}"

        burst_events.append(
            make_event(
                timestamp=burst_start + timedelta(milliseconds=i * 100),
                destination_ip=destination_ip,
                destination_port=443,
            )
        )

    return baseline_events + burst_events


def send_events(events: list[dict]) -> None:
    response = httpx.post(
        f"{API_URL}/events/batch",
        json={"events": events},
        timeout=30,
    )

    response.raise_for_status()

    print(f"Successfully generated {len(events)} events.")
    print(f"Simulated incident PID: {SIMULATED_PID}")


def main() -> None:
    wait_for_api()
    events = generate_events()
    send_events(events)


if __name__ == "__main__":
    main()
