import socket
import sys
from pathlib import Path

from collector.event_parser import (
    ConnectionEvent,
    ConnectionEventV6,
)


FIXTURE_DIRECTORY = (
    Path(__file__).parent / "fixtures"
)


def generate_ipv4_fixture():
    event = ConnectionEvent()

    event.timestamp_ns = 5_000_000_000
    event.duration_ns = 12_500_000
    event.pid = 4242
    event.uid = 1000

    event.destination_ip = int.from_bytes(
        socket.inet_aton("203.0.113.10"),
        byteorder=sys.byteorder,
    )

    event.destination_port = socket.htons(443)
    event.ip_version = 4
    event.process_name = b"python"

    path = FIXTURE_DIRECTORY / "ipv4_event.bin"
    path.write_bytes(bytes(event))


def generate_ipv6_fixture():
    event = ConnectionEventV6()

    event.timestamp_ns = 8_000_000_000
    event.duration_ns = 25_000_000
    event.pid = 5252
    event.uid = 1001

    address_bytes = socket.inet_pton(
        socket.AF_INET6,
        "2001:db8::25",
    )

    for index, value in enumerate(address_bytes):
        event.destination_ip[index] = value

    event.destination_port = socket.htons(8443)
    event.ip_version = 6
    event.process_name = b"curl"

    path = FIXTURE_DIRECTORY / "ipv6_event.bin"
    path.write_bytes(bytes(event))


def main():
    FIXTURE_DIRECTORY.mkdir(
        parents=True,
        exist_ok=True,
    )

    generate_ipv4_fixture()
    generate_ipv6_fixture()

    print(
        f"Fixtures written to {FIXTURE_DIRECTORY}"
    )


if __name__ == "__main__":
    main()
