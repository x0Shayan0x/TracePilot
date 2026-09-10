#!/usr/bin/env python3

import argparse
import ctypes
import json
import os
import socket
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

from bcc import BPF


BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/in.h>
#include <net/sock.h>

struct pending_connection_t {
    u64 start_ns;
    u32 pid;
    u32 uid;
    u32 destination_ip;
    u16 destination_port;
    char process_name[TASK_COMM_LEN];
};

struct connection_event_t {
    u64 timestamp_ns;
    u64 duration_ns;
    u32 pid;
    u32 uid;
    u32 destination_ip;
    u16 destination_port;
    u8 ip_version;
    char process_name[TASK_COMM_LEN];
};

BPF_HASH(pending_connections, u64, struct pending_connection_t);
BPF_PERF_OUTPUT(connection_events);

int trace_tcp_v4_connect_entry(
    struct pt_regs *ctx,
    struct sock *sk,
    struct sockaddr *uaddr,
    int address_length
) {
    u64 process_thread_id = bpf_get_current_pid_tgid();
    u64 user_group_id = bpf_get_current_uid_gid();

    struct sockaddr_in destination = {};
    bpf_probe_read_kernel(
        &destination,
        sizeof(destination),
        uaddr
    );

    if (destination.sin_family != AF_INET) {
        return 0;
    }

    struct pending_connection_t pending = {};

    pending.start_ns = bpf_ktime_get_ns();
    pending.pid = process_thread_id >> 32;
    pending.uid = (u32)user_group_id;
    pending.destination_ip = destination.sin_addr.s_addr;
    pending.destination_port = destination.sin_port;

    bpf_get_current_comm(
        &pending.process_name,
        sizeof(pending.process_name)
    );

    pending_connections.update(
        &process_thread_id,
        &pending
    );

    return 0;
}

int trace_tcp_v4_connect_return(struct pt_regs *ctx) {
    u64 process_thread_id = bpf_get_current_pid_tgid();

    struct pending_connection_t *pending =
        pending_connections.lookup(&process_thread_id);

    if (pending == 0) {
        return 0;
    }

    int return_value = PT_REGS_RC(ctx);

    /*
     * Only emit connections for which tcp_v4_connect()
     * reported success.
     */
    if (return_value != 0) {
        pending_connections.delete(&process_thread_id);
        return 0;
    }

    struct connection_event_t event = {};

    u64 current_time = bpf_ktime_get_ns();

    event.timestamp_ns = pending->start_ns;
    event.duration_ns = current_time - pending->start_ns;
    event.pid = pending->pid;
    event.uid = pending->uid;
    event.destination_ip = pending->destination_ip;
    event.destination_port = pending->destination_port;
    event.ip_version = 4;

    __builtin_memcpy(
        &event.process_name,
        pending->process_name,
        sizeof(event.process_name)
    );

    connection_events.perf_submit(
        ctx,
        &event,
        sizeof(event)
    );

    pending_connections.delete(&process_thread_id);

    return 0;
}

struct pending_connection_v6_t {
    u64 start_ns;
    u32 pid;
    u32 uid;
    unsigned char destination_ip[16];
    u16 destination_port;
    char process_name[TASK_COMM_LEN];
};

struct connection_event_v6_t {
    u64 timestamp_ns;
    u64 duration_ns;
    u32 pid;
    u32 uid;
    unsigned char destination_ip[16];
    u16 destination_port;
    u8 ip_version;
    char process_name[TASK_COMM_LEN];
};

BPF_HASH(
    pending_connections_v6,
    u64,
    struct pending_connection_v6_t
);

BPF_PERF_OUTPUT(connection_events_v6);

int trace_tcp_v6_connect_entry(
    struct pt_regs *ctx,
    struct sock *sk,
    struct sockaddr *uaddr,
    int address_length
) {
    u64 process_thread_id = bpf_get_current_pid_tgid();
    u64 user_group_id = bpf_get_current_uid_gid();

    struct sockaddr_in6 destination = {};

    bpf_probe_read_kernel(
        &destination,
        sizeof(destination),
        uaddr
    );

    if (destination.sin6_family != AF_INET6) {
        return 0;
    }

    struct pending_connection_v6_t pending = {};

    pending.start_ns = bpf_ktime_get_ns();
    pending.pid = process_thread_id >> 32;
    pending.uid = (u32)user_group_id;
    pending.destination_port = destination.sin6_port;

    __builtin_memcpy(
        pending.destination_ip,
        destination.sin6_addr.in6_u.u6_addr8,
        16
    );

    bpf_get_current_comm(
        &pending.process_name,
        sizeof(pending.process_name)
    );

    pending_connections_v6.update(
        &process_thread_id,
        &pending
    );

    return 0;
}

int trace_tcp_v6_connect_return(struct pt_regs *ctx) {
    u64 process_thread_id = bpf_get_current_pid_tgid();

    struct pending_connection_v6_t *pending =
        pending_connections_v6.lookup(&process_thread_id);

    if (pending == 0) {
        return 0;
    }

    int return_value = PT_REGS_RC(ctx);

    if (return_value != 0) {
        pending_connections_v6.delete(&process_thread_id);
        return 0;
    }

    struct connection_event_v6_t event = {};
    u64 current_time = bpf_ktime_get_ns();

    event.timestamp_ns = pending->start_ns;
    event.duration_ns = current_time - pending->start_ns;
    event.pid = pending->pid;
    event.uid = pending->uid;
    event.destination_port = pending->destination_port;
    event.ip_version = 6;

    __builtin_memcpy(
        event.destination_ip,
        pending->destination_ip,
        16
    );

    __builtin_memcpy(
        &event.process_name,
        pending->process_name,
        sizeof(event.process_name)
    );

    connection_events_v6.perf_submit(
        ctx,
        &event,
        sizeof(event)
    );

    pending_connections_v6.delete(&process_thread_id);

    return 0;
}
"""


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

BATCH_SIZE = 50
FLUSH_INTERVAL_SECONDS = 1.0

pending_events = []
api_url = ""
collector_pid = os.getpid()

# Convert the kernel's monotonic timestamp to Unix wall-clock time.
wall_clock_offset_ns = time.time_ns() - time.monotonic_ns()


def kernel_time_to_datetime(timestamp_ns):
    unix_timestamp_ns = wall_clock_offset_ns + timestamp_ns

    return datetime.fromtimestamp(
        unix_timestamp_ns / 1_000_000_000,
        tz=timezone.utc,
    )


def handle_event(cpu, data, size):
    event = ctypes.cast(
        data,
        ctypes.POINTER(ConnectionEvent),
    ).contents

    # Ignore connections created by this collector itself.
    # Otherwise, posting a batch to the API would generate
    # another network event and create a feedback loop.
    if event.pid == collector_pid:
        return

    destination_ip = socket.inet_ntoa(
        ctypes.string_at(
            ctypes.byref(
                ctypes.c_uint32(event.destination_ip)
            ),
            4,
        )
    )

    destination_port = socket.ntohs(
        event.destination_port
    )
    
    if destination_port in {8000, 5432}:
        return

    process_name = (
        bytes(event.process_name)
        .split(b"\0", 1)[0]
        .decode("utf-8", errors="replace")
    )

    timestamp = kernel_time_to_datetime(
        event.timestamp_ns
    )

    api_event = {
        "timestamp": timestamp.isoformat(),
        "pid": event.pid,
        "process_name": process_name,
        "uid": event.uid,
        "destination_ip": destination_ip,
        "destination_port": destination_port,
        "ip_version": event.ip_version,
        "duration_ms": event.duration_ns / 1_000_000,
        "source": "ebpf",
    }

    pending_events.append(api_event)

    print(
        f"Captured PID={event.pid} "
        f"COMM={process_name} "
        f"DEST={destination_ip}:{destination_port}"
    )
    
def handle_ipv6_event(cpu, data, size):
    event = ctypes.cast(
        data,
        ctypes.POINTER(ConnectionEventV6),
    ).contents

    if event.pid == collector_pid:
        return

    destination_port = socket.ntohs(
        event.destination_port
    )

    if destination_port in {8000, 5432}:
        return

    destination_ip = socket.inet_ntop(
        socket.AF_INET6,
        bytes(event.destination_ip),
    )

    process_name = (
        bytes(event.process_name)
        .split(b"\0", 1)[0]
        .decode("utf-8", errors="replace")
    )

    timestamp = kernel_time_to_datetime(
        event.timestamp_ns
    )

    pending_events.append(
        {
            "timestamp": timestamp.isoformat(),
            "pid": event.pid,
            "process_name": process_name,
            "uid": event.uid,
            "destination_ip": destination_ip,
            "destination_port": destination_port,
            "ip_version": 6,
            "duration_ms": event.duration_ns / 1_000_000,
            "source": "ebpf",
        }
    )

    print(
        f"Captured IPv6 PID={event.pid} "
        f"COMM={process_name} "
        f"DEST=[{destination_ip}]:{destination_port}"
    )


def handle_lost_events(cpu, lost_count):
    print(
        f"Warning: lost {lost_count} events on CPU {cpu}"
    )


def send_one_batch():
    if not pending_events:
        return True

    batch = pending_events[:500]

    request_body = json.dumps(
        {"events": batch}
    ).encode("utf-8")

    request = urllib.request.Request(
        f"{api_url}/events/batch",
        data=request_body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )

    try:
        with urllib.request.urlopen(
            request,
            timeout=10,
        ) as response:
            if response.status != 201:
                print(
                    f"API returned unexpected status: "
                    f"{response.status}"
                )
                return False

    except urllib.error.HTTPError as error:
        response_body = error.read().decode(
            "utf-8",
            errors="replace",
        )

        print(
            f"API rejected batch: "
            f"{error.code} {response_body}"
        )
        return False

    except urllib.error.URLError as error:
        print(f"Could not reach API: {error.reason}")
        return False

    except TimeoutError:
        print("API request timed out.")
        return False

    del pending_events[:len(batch)]

    print(f"Sent {len(batch)} events to TracePilot.")

    return True


def flush_pending_events():
    while pending_events:
        if not send_one_batch():
            break


def parse_arguments():
    parser = argparse.ArgumentParser(
        description="TracePilot eBPF TCP collector"
    )

    parser.add_argument(
        "--api",
        default="http://localhost:8000",
        help="TracePilot API base URL",
    )

    return parser.parse_args()


def main():
    global api_url

    arguments = parse_arguments()
    api_url = arguments.api.rstrip("/")

    bpf = BPF(text=BPF_PROGRAM)

    bpf.attach_kprobe(
        event="tcp_v4_connect",
        fn_name="trace_tcp_v4_connect_entry",
    )

    bpf.attach_kretprobe(
        event="tcp_v4_connect",
        fn_name="trace_tcp_v4_connect_return",
    )
    
    bpf.attach_kprobe(
        event="tcp_v6_connect",
        fn_name="trace_tcp_v6_connect_entry",
    )

    bpf.attach_kretprobe(
        event="tcp_v6_connect",
        fn_name="trace_tcp_v6_connect_return",
    )

    bpf["connection_events"].open_perf_buffer(
        handle_event,
        lost_cb=handle_lost_events,
    )
    
    bpf["connection_events_v6"].open_perf_buffer(
        handle_ipv6_event,
        lost_cb=handle_lost_events,
    )

    print("Tracing outbound IPv4 and IPv6 TCP connections...")
    print(f"Sending events to {api_url}")
    print("Press Ctrl+C to stop.")

    last_flush_time = time.monotonic()

    try:
        while True:
            # Timeout allows the loop to check the flush timer
            # even when no new connections occur.
            bpf.perf_buffer_poll(timeout=100)

            current_time = time.monotonic()

            batch_is_full = (
                len(pending_events) >= BATCH_SIZE
            )

            flush_time_reached = (
                pending_events
                and current_time - last_flush_time
                >= FLUSH_INTERVAL_SECONDS
            )

            if batch_is_full or flush_time_reached:
                flush_pending_events()
                last_flush_time = current_time

    except KeyboardInterrupt:
        print("\nStopping collector.")

        if pending_events:
            print(
                f"Flushing {len(pending_events)} "
                f"remaining events..."
            )
            flush_pending_events()


if __name__ == "__main__":
    main()
