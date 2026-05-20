#!/usr/bin/env python3
"""
BCC eBPF runner for the ClawAegis sentinel.

Attaches to syscall tracepoints (execve, openat, connect) and emits one
JSONL object per event to stdout. The Node loader (`sentinel/probes/ebpf/
loader.ts`) reads stdout line-by-line.

This script is intentionally simple and Linux-only — it is invoked as a
child process by the Node loader, never imported. Stderr is reserved for
fatal diagnostics; stdout is the wire protocol.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time

try:
    from bcc import BPF  # type: ignore[import-untyped]
except ImportError:
    print(
        json.dumps({
            "kind": "log",
            "level": "error",
            "message": "bcc python module not installed; eBPF probe cannot start",
        }),
        flush=True,
    )
    sys.exit(2)


BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct exec_evt_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
};
BPF_PERF_OUTPUT(exec_events);

struct file_evt_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char path[256];
};
BPF_PERF_OUTPUT(file_events);

struct net_evt_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(net_events);

TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct exec_evt_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    evt.ppid = t->real_parent->tgid;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(evt.filename, sizeof(evt.filename), args->filename);
    exec_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct file_evt_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    evt.ppid = t->real_parent->tgid;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(evt.path, sizeof(evt.path), args->filename);
    file_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct net_evt_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    evt.ppid = t->real_parent->tgid;
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    net_events.perf_submit(args, &evt, sizeof(evt));
    return 0;
}
"""


def emit(obj):
    print(json.dumps(obj), flush=True)


def log(level, message):
    emit({"kind": "log", "level": level, "message": message})


def now_ms():
    return int(time.time() * 1000)


def make_exec_handler(targets):
    def cb(cpu, data, size):
        evt = bpf["exec_events"].event(data)
        if "execve" not in targets:
            return
        emit({
            "kind": "syscall",
            "syscall": "execve",
            "pid": int(evt.pid),
            "ppid": int(evt.ppid),
            "ts": now_ms(),
            "comm": evt.comm.decode("utf-8", "replace").strip("\x00"),
            "path": evt.filename.decode("utf-8", "replace").strip("\x00"),
        })

    return cb


def make_file_handler(targets):
    def cb(cpu, data, size):
        evt = bpf["file_events"].event(data)
        if "openat" not in targets:
            return
        emit({
            "kind": "syscall",
            "syscall": "openat",
            "pid": int(evt.pid),
            "ppid": int(evt.ppid),
            "ts": now_ms(),
            "comm": evt.comm.decode("utf-8", "replace").strip("\x00"),
            "path": evt.path.decode("utf-8", "replace").strip("\x00"),
        })

    return cb


def make_net_handler(targets):
    def cb(cpu, data, size):
        evt = bpf["net_events"].event(data)
        if "connect" not in targets:
            return
        emit({
            "kind": "syscall",
            "syscall": "connect",
            "pid": int(evt.pid),
            "ppid": int(evt.ppid),
            "ts": now_ms(),
            "comm": evt.comm.decode("utf-8", "replace").strip("\x00"),
        })

    return cb


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--targets",
        default="execve,openat,connect",
        help="Comma-separated subset of {execve, openat, connect}.",
    )
    args = parser.parse_args()
    targets = set(t.strip() for t in args.targets.split(",") if t.strip())

    global bpf
    try:
        bpf = BPF(text=BPF_PROGRAM)
    except Exception as exc:  # pylint: disable=broad-except
        log("error", "BPF program load failed: %s" % exc)
        sys.exit(3)

    bpf["exec_events"].open_perf_buffer(make_exec_handler(targets))
    bpf["file_events"].open_perf_buffer(make_file_handler(targets))
    bpf["net_events"].open_perf_buffer(make_net_handler(targets))

    emit({"kind": "ready", "probes": sorted(targets)})

    while True:
        try:
            bpf.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            return
        except Exception as exc:  # pylint: disable=broad-except
            log("error", "perf_buffer_poll threw: %s" % exc)
            return


if __name__ == "__main__":
    if os.geteuid() != 0:
        log("warn", "eBPF probe is not running as root; tracepoint attach will likely fail")
    main()
