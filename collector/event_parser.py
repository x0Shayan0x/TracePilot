import ctypes
import socket
import sys
from datetime import datetime, timezone


class ConnectionEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("duration_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("destination_ip", ctypes.c_uint32),
        ("destination_port", ctypes.c_uint16),
        ("ip_version", ctypes.c_uint8),
        ("process_name", ctypes.c_char * 16),
    ]


class ConnectionEventV6(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("duration_ns", ctypes.c_uint64),
        ("pid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32),
        ("destination_ip", ctypes.c_ubyte * 16),
        ("destination_port", ctypes.c_uint16),
        ("ip_version", ctypes.c_uint8),
        ("process_name", ctypes.c_char * 16),
    ]


def kernel_time_to_datetime(
    timestamp_ns: int,
    wall_clock_offset_ns: int,
) -> datetime:
    unix_timestamp_ns = (
        wall_clock_offset_ns + timestamp_ns
    )

    return datetime.fromtimestamp(
        unix_timestamp_ns / 1_000_000_000,
        tz=timezone.utc,
    )


def decode_process_name(raw_name: bytes) -> str:
    return (
        raw_name
        .split(b"\0", 1)[0]
        .decode("utf-8", errors="replace")
    )


def _read_structure(
    raw_event: bytes,
    structure_type,
):
    expected_size = ctypes.sizeof(structure_type)

    if len(raw_event) != expected_size:
        raise ValueError(
            "Invalid event size: "
            f"expected {expected_size}, "
            f"received {len(raw_event)}"
        )

    return structure_type.from_buffer_copy(raw_event)


def parse_ipv4_event(
    raw_event: bytes,
    wall_clock_offset_ns: int,
) -> dict:
    event = _read_structure(
        raw_event,
        ConnectionEvent,
    )

    if event.ip_version != 4:
        raise ValueError(
            f"Expected IPv4 event, got version "
            f"{event.ip_version}"
        )

    # destination_ip contains the four bytes copied from
    # sockaddr_in. Recreate those bytes in host byte order.
    ip_bytes = event.destination_ip.to_bytes(
        4,
        byteorder=sys.byteorder,
    )

    destination_ip = socket.inet_ntoa(ip_bytes)

    destination_port = socket.ntohs(
        event.destination_port
    )

    timestamp = kernel_time_to_datetime(
        event.timestamp_ns,
        wall_clock_offset_ns,
    )

    return {
        "timestamp": timestamp.isoformat(),
        "pid": event.pid,
        "process_name": decode_process_name(
            bytes(event.process_name)
        ),
        "uid": event.uid,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "ip_version": 4,
        "duration_ms": (
            event.duration_ns / 1_000_000
        ),
        "source": "ebpf",
    }


def parse_ipv6_event(
    raw_event: bytes,
    wall_clock_offset_ns: int,
) -> dict:
    event = _read_structure(
        raw_event,
        ConnectionEventV6,
    )

    if event.ip_version != 6:
        raise ValueError(
            f"Expected IPv6 event, got version "
            f"{event.ip_version}"
        )

    destination_ip = socket.inet_ntop(
        socket.AF_INET6,
        bytes(event.destination_ip),
    )

    destination_port = socket.ntohs(
        event.destination_port
    )

    timestamp = kernel_time_to_datetime(
        event.timestamp_ns,
        wall_clock_offset_ns,
    )

    return {
        "timestamp": timestamp.isoformat(),
        "pid": event.pid,
        "process_name": decode_process_name(
            bytes(event.process_name)
        ),
        "uid": event.uid,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "ip_version": 6,
        "duration_ms": (
            event.duration_ns / 1_000_000
        ),
        "source": "ebpf",
    }
