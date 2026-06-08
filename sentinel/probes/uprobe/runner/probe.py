#!/usr/bin/env python3
"""
BCC uprobe runner for the AgentAegis sentinel.

Unlike sibling tracepoint runner (../../ebpf/runner/probe.py), this script
attaches uprobes on **user-space symbols** in the configured libc (and
optionally libssl). Uprobes see the parameters as the application passed them
to libc — for openssl this means *plaintext before encryption*, which
tracepoints can no longer recover.

Wire protocol is identical to the eBPF runner: one JSON object per stdout
line. The TS loader (../loader.ts) treats both runners interchangeably.

This script is invoked as a child process by Node, never imported.
"""

from __future__ import annotations

import argparse
import ctypes as ct
import json
import os
import sys
import time

# Must match the C struct literal sizes below.
MAX_ARGV = 8
MAX_ARG_LEN = 64
TASK_COMM_LEN = 16
PATH_LEN = 256
PREVIEW_LEN = 128


class ExecEvtT(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("filename", ct.c_char * PATH_LEN),
        ("argc", ct.c_uint32),
        ("argv", (ct.c_char * MAX_ARG_LEN) * MAX_ARGV),
    ]


class FileEvtT(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("path", ct.c_char * PATH_LEN),
    ]


class NetEvtT(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("comm", ct.c_char * TASK_COMM_LEN),
    ]


class SslEvtT(ct.Structure):
    _fields_ = [
        ("pid", ct.c_uint32),
        ("ppid", ct.c_uint32),
        ("comm", ct.c_char * TASK_COMM_LEN),
        ("op", ct.c_uint32),  # 0 = write, 1 = read
        ("preview", ct.c_char * PREVIEW_LEN),
        ("size", ct.c_uint32),
    ]


try:
    from bcc import BPF  # type: ignore[import-untyped]
except ImportError:
    print(
        json.dumps(
            {
                "kind": "log",
                "level": "error",
                "message": "bcc python module not installed; uprobe probe cannot start",
            }
        ),
        flush=True,
    )
    sys.exit(2)


BPF_LIBC_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define MAX_ARGV 8
#define MAX_ARG_LEN 64
#define PATH_LEN 256

struct exec_evt_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char filename[PATH_LEN];
    u32 argc;
    char argv[MAX_ARGV][MAX_ARG_LEN];
};
BPF_PERF_OUTPUT(exec_events);
BPF_PERCPU_ARRAY(exec_scratch, struct exec_evt_t, 1);

struct file_evt_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    char path[PATH_LEN];
};
BPF_PERF_OUTPUT(file_events);

struct net_evt_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
};
BPF_PERF_OUTPUT(net_events);

static __always_inline u32 get_ppid(void) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    return t->real_parent->tgid;
}

int trace_execve(struct pt_regs *ctx, const char *filename, const char *const *argv) {
    u32 zero = 0;
    struct exec_evt_t *evt = exec_scratch.lookup(&zero);
    if (!evt) return 0;
    evt->pid = bpf_get_current_pid_tgid() >> 32;
    evt->ppid = get_ppid();
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    bpf_probe_read_user_str(evt->filename, sizeof(evt->filename), (void *)filename);
    evt->argc = 0;

    #pragma unroll
    for (int i = 0; i < MAX_ARGV; i++) {
        const char *one = NULL;
        if (bpf_probe_read_user(&one, sizeof(one), &argv[i]) != 0) break;
        if (one == NULL) break;
        bpf_probe_read_user_str(evt->argv[i], MAX_ARG_LEN, one);
        evt->argc = i + 1;
    }

    exec_events.perf_submit(ctx, evt, sizeof(*evt));
    return 0;
}

int trace_open(struct pt_regs *ctx, const char *pathname) {
    struct file_evt_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.ppid = get_ppid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    bpf_probe_read_user_str(evt.path, sizeof(evt.path), (void *)pathname);
    file_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

// glibc openat: signature is (int dirfd, const char *pathname, int flags, ...)
// pathname is the 2nd argument, so PT_REGS_PARM2.
int trace_openat(struct pt_regs *ctx) {
    struct file_evt_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.ppid = get_ppid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    const char *pathname = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(evt.path, sizeof(evt.path), (void *)pathname);
    file_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

int trace_connect(struct pt_regs *ctx) {
    struct net_evt_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.ppid = get_ppid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    net_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}
"""

BPF_SSL_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

#define PREVIEW_LEN 128

struct ssl_evt_t {
    u32 pid;
    u32 ppid;
    char comm[TASK_COMM_LEN];
    u32 op;
    char preview[PREVIEW_LEN];
    u32 size;
};
BPF_PERF_OUTPUT(ssl_events);

static __always_inline u32 get_ppid(void) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    return t->real_parent->tgid;
}

int trace_ssl_write(struct pt_regs *ctx, void *ssl, const void *buf, int num) {
    struct ssl_evt_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.ppid = get_ppid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.op = 0;
    evt.size = (u32)num;
    bpf_probe_read_user(evt.preview, sizeof(evt.preview), (void *)buf);
    ssl_events.perf_submit(ctx, &evt, sizeof(evt));
    return 0;
}

int trace_ssl_read(struct pt_regs *ctx, void *ssl, void *buf, int num) {
    struct ssl_evt_t evt = {};
    evt.pid = bpf_get_current_pid_tgid() >> 32;
    evt.ppid = get_ppid();
    bpf_get_current_comm(&evt.comm, sizeof(evt.comm));
    evt.op = 1;
    evt.size = (u32)num;
    bpf_probe_read_user(evt.preview, sizeof(evt.preview), (void *)buf);
    ssl_events.perf_submit(ctx, &evt, sizeof(evt));
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
        emit(
            {
                "kind": "syscall",
                "syscall": "execve",
                "pid": int(evt.pid),
                "ppid": int(evt.ppid),
                "ts": now_ms(),
                "comm": evt.comm.decode("utf-8", "replace").strip("\x00"),
                "path": evt.filename.decode("utf-8", "replace").strip("\x00"),
                "argv": argv,
            }
        )

    return cb


def make_file_handler(targets):
    def cb(cpu, data, size):
        if "openat" not in targets:
            return
        evt = ct.cast(data, ct.POINTER(FileEvtT)).contents
        emit(
            {
                "kind": "syscall",
                "syscall": "openat",
                "pid": int(evt.pid),
                "ppid": int(evt.ppid),
                "ts": now_ms(),
                "comm": evt.comm.decode("utf-8", "replace").strip("\x00"),
                "path": evt.path.decode("utf-8", "replace").strip("\x00"),
            }
        )

    return cb


def make_net_handler(targets):
    def cb(cpu, data, size):
        if "connect" not in targets:
            return
        evt = ct.cast(data, ct.POINTER(NetEvtT)).contents
        emit(
            {
                "kind": "syscall",
                "syscall": "connect",
                "pid": int(evt.pid),
                "ppid": int(evt.ppid),
                "ts": now_ms(),
                "comm": evt.comm.decode("utf-8", "replace").strip("\x00"),
            }
        )

    return cb


def make_ssl_handler(targets):
    def cb(cpu, data, size):
        evt = ct.cast(data, ct.POINTER(SslEvtT)).contents
        op = "SSL_write" if int(evt.op) == 0 else "SSL_read"
        if op not in targets:
            return
        emit(
            {
                "kind": "syscall",
                "syscall": op,
                "pid": int(evt.pid),
                "ppid": int(evt.ppid),
                "ts": now_ms(),
                "comm": evt.comm.decode("utf-8", "replace").strip("\x00"),
                "preview": evt.preview.decode("utf-8", "replace").rstrip("\x00"),
                "extra": {"size": int(evt.size)},
            }
        )

    return cb


def attach_libc(bpf, libc_path, targets):
    attached = set()
    if "execve" in targets:
        for sym in ("execve", "execvp"):
            try:
                bpf.attach_uprobe(name=libc_path, sym=sym, fn_name="trace_execve")
                attached.add("execve")
            except Exception as exc:
                log("warn", "attach %s failed: %s" % (sym, exc))
    if "openat" in targets:
        for sym, fn in (("openat", "trace_openat"), ("openat64", "trace_openat")):
            try:
                bpf.attach_uprobe(name=libc_path, sym=sym, fn_name=fn)
                attached.add("openat")
            except Exception as exc:
                log("warn", "attach %s failed: %s" % (sym, exc))
        # Also try plain "open" (Node on some platforms goes through it).
        try:
            bpf.attach_uprobe(name=libc_path, sym="open", fn_name="trace_open")
            attached.add("openat")
        except Exception as exc:
            log("debug", "attach open failed (non-fatal): %s" % exc)
    if "connect" in targets:
        try:
            bpf.attach_uprobe(name=libc_path, sym="connect", fn_name="trace_connect")
            attached.add("connect")
        except Exception as exc:
            log("warn", "attach connect failed: %s" % exc)
    return attached


def attach_ssl(bpf, openssl_path, targets):
    attached = set()
    if "SSL_write" in targets:
        try:
            bpf.attach_uprobe(name=openssl_path, sym="SSL_write", fn_name="trace_ssl_write")
            attached.add("SSL_write")
        except Exception as exc:
            log("warn", "attach SSL_write failed: %s" % exc)
    if "SSL_read" in targets:
        try:
            bpf.attach_uprobe(name=openssl_path, sym="SSL_read", fn_name="trace_ssl_read")
            attached.add("SSL_read")
        except Exception as exc:
            log("warn", "attach SSL_read failed: %s" % exc)
    return attached


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--targets",
        default="execve,openat,connect",
        help="Comma-separated subset of {execve, openat, connect, SSL_write, SSL_read}.",
    )
    parser.add_argument("--libc-path", required=True, help="Absolute path to libc.so")
    parser.add_argument("--openssl-path", default=None, help="Absolute path to libssl.so")
    args = parser.parse_args()
    targets = set(t.strip() for t in args.targets.split(",") if t.strip())

    libc_targets = {t for t in targets if t in ("execve", "openat", "connect")}
    ssl_targets = {t for t in targets if t in ("SSL_write", "SSL_read")}

    bpfs = []
    attached_all = set()

    if libc_targets:
        try:
            bpf_libc = BPF(text=BPF_LIBC_PROGRAM)
        except Exception as exc:
            log("error", "BPF libc program load failed: %s" % exc)
            sys.exit(3)
        attached_all |= attach_libc(bpf_libc, args.libc_path, libc_targets)
        if "execve" in attached_all:
            bpf_libc["exec_events"].open_perf_buffer(make_exec_handler(targets))
        if "openat" in attached_all:
            bpf_libc["file_events"].open_perf_buffer(make_file_handler(targets))
        if "connect" in attached_all:
            bpf_libc["net_events"].open_perf_buffer(make_net_handler(targets))
        bpfs.append(bpf_libc)

    if ssl_targets:
        if not args.openssl_path:
            log("warn", "SSL_* requested but --openssl-path not provided")
        else:
            try:
                bpf_ssl = BPF(text=BPF_SSL_PROGRAM)
            except Exception as exc:
                log("error", "BPF ssl program load failed: %s" % exc)
                sys.exit(4)
            attached_all |= attach_ssl(bpf_ssl, args.openssl_path, ssl_targets)
            if "SSL_write" in attached_all or "SSL_read" in attached_all:
                bpf_ssl["ssl_events"].open_perf_buffer(make_ssl_handler(targets))
            bpfs.append(bpf_ssl)

    if not bpfs:
        log("error", "no BPF objects loaded; nothing to do")
        sys.exit(5)

    emit({"kind": "ready", "probes": sorted(attached_all)})

    while True:
        try:
            for b in bpfs:
                b.perf_buffer_poll(timeout=1000)
        except KeyboardInterrupt:
            return
        except Exception as exc:
            log("error", "perf_buffer_poll threw: %s" % exc)
            return


if __name__ == "__main__":
    if os.geteuid() != 0:
        log(
            "warn",
            "uprobe runner is not running as root; uprobe attach will likely fail",
        )
    main()
