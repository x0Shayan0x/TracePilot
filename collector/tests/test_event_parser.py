from pathlib import Path

import pytest

from collector.event_parser import (
    parse_ipv4_event,
    parse_ipv6_event,
)


FIXTURES = Path(__file__).parent / "fixtures"

WALL_CLOCK_OFFSET_NS = (
    1_700_000_000_000_000_000
)


def test_parse_saved_ipv4_event():
    raw_event = (
        FIXTURES / "ipv4_event.bin"
    ).read_bytes()

    event = parse_ipv4_event(
        raw_event,
        WALL_CLOCK_OFFSET_NS,
    )

    assert event == {
        "timestamp": (
            "2023-11-14T22:13:25+00:00"
        ),
        "pid": 4242,
        "process_name": "python",
        "uid": 1000,
        "destination_ip": "203.0.113.10",
        "destination_port": 443,
        "ip_version": 4,
        "duration_ms": 12.5,
        "source": "ebpf",
    }


def test_parse_saved_ipv6_event():
    raw_event = (
        FIXTURES / "ipv6_event.bin"
    ).read_bytes()

    event = parse_ipv6_event(
        raw_event,
        WALL_CLOCK_OFFSET_NS,
    )

    assert event == {
        "timestamp": (
            "2023-11-14T22:13:28+00:00"
        ),
        "pid": 5252,
        "process_name": "curl",
        "uid": 1001,
        "destination_ip": "2001:db8::25",
        "destination_port": 8443,
        "ip_version": 6,
        "duration_ms": 25.0,
        "source": "ebpf",
    }


@pytest.mark.parametrize(
    "parser",
    [
        parse_ipv4_event,
        parse_ipv6_event,
    ],
)
def test_rejects_malformed_event_size(parser):
    with pytest.raises(
        ValueError,
        match="Invalid event size",
    ):
        parser(
            b"\x00\x01",
            WALL_CLOCK_OFFSET_NS,
        )
