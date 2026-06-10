#!/usr/bin/env python3
"""
BCC eBPF runner for the AgentAegis sentinel.

Attaches to syscall tracepoints (execve, openat, connect) and emits one
JSONL object per event to stdout. The Node loader (`sentinel/probes/ebpf/
loader.ts`) reads stdout line-by-line.

This script is intentionally simple and Linux-only — it is invoked as a
child process by the Node loader, never imported. Stderr is reserved for
fatal diagnostics; stdout is the wire protocol.

Kept compatible with the distro system python3: RHEL/CentOS/Anolis/Alinux 7
ship python 3.6, which is also where the `python3-bcc` package installs — so
BCC is only importable by that 3.6 interpreter. Therefore NO `from __future__
import annotations` and no 3.7+ syntax here. The script carries no type
annotations that would need it.
"""

import argparse
import ctypes as ct
import json
import os
import sys
import time

# Must match the C struct exec_evt_t / file_evt_t / net_evt_t literal sizes.
# Kept here (rather than auto-detected via BPF.event()) because nested 2D
# char arrays defeat BCC's automatic ctypes synthesis on recent BCC.
MAX_ARGV = 8
MAX_ARG_LEN = 64
TASK_COMM_LEN = 16


class ExecEvtT(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("filename", ct.c_char * 256),
        ("argc", ct.c_uint32),
        ("argv", (ct.c_char * MAX_ARG_LEN) * MAX_ARGV),
    ]


class FileEvtT(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("path", ct.c_char * 256),
    ]


class NetEvtT(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("comm", ct.c_char * TASK_COMM_LEN),
    ]

try:
    from bcc import BPF  # type: ignore[import-untyped]
except ImportError:
    print(
        json.dumps({
            "kind": "log",
            "level": "error",
            "message": (
                f"bcc python module not importable by this interpreter ({sys.executable}); "
                "eBPF probe cannot start. Install BCC for the SYSTEM python3 — "
                "Debian/Ubuntu: `apt install -y bpfcc-tools python3-bpfcc`; "
                "RHEL/CentOS/Anolis/Alinux: `yum install -y bcc-tools python3-bcc`. "
                "Then run with THAT interpreter (a pyenv/conda/venv python will not see "
                "the distro-installed bcc)."
            ),
        }),
        flush=True,
    )
    sys.exit(2)


BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_ARGV 8
#define MAX_ARG_LEN 64

struct exec_evt_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[256];
    u32 argc;
    char argv[MAX_ARGV][MAX_ARG_LEN];
};
BPF_PERF_OUTPUT(exec_events);
// exec_evt_t is too large for the 512-byte BPF stack; back it with a
// per-CPU scratch map so each CPU has its own reusable slot.
BPF_PERCPU_ARRAY(exec_scratch, struct exec_evt_t, 1);

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
    u32 zero = 0;
    struct exec_evt_t *evt = exec_scratch.lookup(&zero);
    if (!evt) return 0;
    // Re-initialise the slot — per-CPU map storage is reused across calls.
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    evt->ppid = t->real_parent->tgid;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), args->filename);
    evt->argc = 0;

    // Walk argv. The verifier requires a bounded loop — MAX_ARGV chosen to
    // cover typical shell commands while keeping the event under perf_buf
    // record limits. Strings longer than MAX_ARG_LEN-1 are truncated.
    const char *const *argv_ptr = (const char *const *)args->argv;
    #pragma unroll
    for (int i = 0; i < MAX_ARGV; i++) {
        const char *one = NULL;
        if (bpf_probe_read_user(&one, sizeof(one), &argv_ptr[i]) != 0) break;
        if (one == NULL) break;
        bpf_probe_read_user_str(evt->argv[i], MAX_ARG_LEN, one);
        evt->argc = i + 1;
    }

    exec_events.perf_submit(args, evt, sizeof(*evt));
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
        if "execve" not in targets:
            return
        evt = ct.cast(data, ct.POINTER(ExecEvtT)).contents
        argv = []
        argc = int(evt.argc)
        for i in range(min(argc, MAX_ARGV)):
            s = bytes(evt.argv[i]).decode("utf-8", "replace").rstrip("\x00")
            if s:
                argv.append(s)
        emit({
            "kind": "syscall",
            "syscall": "execve",
            "pid": int(evt.pid),
            "ppid": int(evt.ppid),
            "ts": now_ms(),
            "comm": evt.comm.decode("utf-8", "replace").strip("\x00"),
            "path": evt.filename.decode("utf-8", "replace").strip("\x00"),
            "argv": argv,
        })

    return cb


def make_file_handler(targets):
    def cb(cpu, data, size):
        if "openat" not in targets:
            return
        evt = ct.cast(data, ct.POINTER(FileEvtT)).contents
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
        if "connect" not in targets:
            return
        evt = ct.cast(data, ct.POINTER(NetEvtT)).contents
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
