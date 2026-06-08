// SPDX-License-Identifier: GPL-2.0
//
// eBPF tracepoint + uprobe programs for AgentAegis "ebpf" / "uprobe" modes.
//
// sys_event is ~750 bytes (path + argv table) which would overflow the
// 512-byte BPF stack. We back it with a per-CPU scratch array and submit
// the contents into a ringbuf as the final event channel.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define TASK_COMM_LEN 16
#define MAX_ARGV 8
#define MAX_ARG_LEN 64
#define PATH_LEN 256

enum syscall_kind {
    SYS_EXECVE = 0,
    SYS_OPENAT = 1,
    SYS_CONNECT = 2,
    SYS_SSL_WRITE = 3,
    SYS_SSL_READ = 4,
};

struct sys_event {
    __u32 kind;
    __u32 pid;
    __u32 ppid;
    char comm[TASK_COMM_LEN];
    char path[PATH_LEN];
    __u32 argc;
    char argv[MAX_ARGV][MAX_ARG_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 18);
} sys_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct sys_event);
} sys_event_scratch SEC(".maps");

static __always_inline __u32 get_ppid(void) {
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    return BPF_CORE_READ(t, real_parent, tgid);
}

static __always_inline struct sys_event *fill_event(__u32 kind) {
    __u32 zero = 0;
    struct sys_event *e = bpf_map_lookup_elem(&sys_event_scratch, &zero);
    if (!e) return NULL;
    __builtin_memset(e, 0, sizeof(*e));
    e->kind = kind;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->ppid = get_ppid();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    return e;
}

static __always_inline int publish(void *ctx, struct sys_event *e) {
    struct sys_event *out = bpf_ringbuf_reserve(&sys_events, sizeof(*out), 0);
    if (!out) return 0;
    __builtin_memcpy(out, e, sizeof(*out));
    bpf_ringbuf_submit(out, 0);
    return 0;
}

// `struct trace_event_raw_sys_enter` is supplied by vmlinux.h. We just use it.

SEC("tracepoint/syscalls/sys_enter_execve")
int tp_sys_enter_execve(struct trace_event_raw_sys_enter *ctx) {
    struct sys_event *e = fill_event(SYS_EXECVE);
    if (!e) return 0;
    const char *filename = (const char *)ctx->args[0];
    bpf_probe_read_user_str(e->path, sizeof(e->path), filename);

    const char *const *argv = (const char *const *)ctx->args[1];
    #pragma unroll
    for (int i = 0; i < MAX_ARGV; i++) {
        const char *one = NULL;
        if (bpf_probe_read_user(&one, sizeof(one), &argv[i]) != 0) break;
        if (!one) break;
        bpf_probe_read_user_str(e->argv[i], MAX_ARG_LEN, one);
        e->argc = i + 1;
    }
    return publish(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_openat")
int tp_sys_enter_openat(struct trace_event_raw_sys_enter *ctx) {
    struct sys_event *e = fill_event(SYS_OPENAT);
    if (!e) return 0;
    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
    return publish(ctx, e);
}

SEC("tracepoint/syscalls/sys_enter_connect")
int tp_sys_enter_connect(struct trace_event_raw_sys_enter *ctx) {
    struct sys_event *e = fill_event(SYS_CONNECT);
    if (!e) return 0;
    return publish(ctx, e);
}

SEC("uprobe/libc:execve")
int up_execve(struct pt_regs *ctx) {
    struct sys_event *e = fill_event(SYS_EXECVE);
    if (!e) return 0;
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
    const char *const *argv = (const char *const *)PT_REGS_PARM2(ctx);
    #pragma unroll
    for (int i = 0; i < MAX_ARGV; i++) {
        const char *one = NULL;
        if (bpf_probe_read_user(&one, sizeof(one), &argv[i]) != 0) break;
        if (!one) break;
        bpf_probe_read_user_str(e->argv[i], MAX_ARG_LEN, one);
        e->argc = i + 1;
    }
    return publish(ctx, e);
}

SEC("uprobe/libc:openat")
int up_openat(struct pt_regs *ctx) {
    struct sys_event *e = fill_event(SYS_OPENAT);
    if (!e) return 0;
    const char *filename = (const char *)PT_REGS_PARM2(ctx);
    bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
    return publish(ctx, e);
}

SEC("uprobe/libc:open")
int up_open(struct pt_regs *ctx) {
    struct sys_event *e = fill_event(SYS_OPENAT);
    if (!e) return 0;
    const char *filename = (const char *)PT_REGS_PARM1(ctx);
    bpf_probe_read_user_str(e->path, sizeof(e->path), filename);
    return publish(ctx, e);
}

SEC("uprobe/libc:connect")
int up_connect(struct pt_regs *ctx) {
    struct sys_event *e = fill_event(SYS_CONNECT);
    if (!e) return 0;
    return publish(ctx, e);
}

char LICENSE[] SEC("license") = "GPL";
