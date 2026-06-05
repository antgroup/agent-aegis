// SPDX-License-Identifier: GPL-2.0
//
// eBPF LSM hooks for ClawAegis enforce mode.
//
// 256-byte path buffers and policy keys exceed the BPF stack limit of 512
// bytes, so all large scratch storage lives in per-CPU array maps.
//
// Loading requires CONFIG_BPF_LSM=y, `bpf` in /sys/kernel/security/lsm,
// Linux ≥ 5.7. The runner exits non-zero on load failure; the loader logs a
// warn and continues with whatever other probes are active.
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#ifndef AF_INET
#define AF_INET 2
#endif

#define POLICY_VALUE_LEN 256
#define MAX_POLICY_ENTRIES 1024

struct policy_key {
    __u32 kind;
    unsigned char value[POLICY_VALUE_LEN];
};

struct policy_val {
    __u64 expires_ns;
    __u32 severity;
    __u32 _pad;        // align to 16 bytes to match Go side
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_POLICY_ENTRIES);
    __type(key, struct policy_key);
    __type(value, struct policy_val);
} policy_map SEC(".maps");

struct deny_event {
    __u32 pid;
    __u32 ppid;
    char comm[16];
    __u32 hook;
    unsigned char match[POLICY_VALUE_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 16);
} deny_events SEC(".maps");

// Per-CPU scratch for the path buffer + policy key. Reusing a single slot
// keeps each invocation off the 512-byte BPF stack.
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct policy_key);
} scratch_key SEC(".maps");

static __always_inline __u64 now_ns(void) {
    return bpf_ktime_get_ns();
}

static __always_inline int emit_deny(__u32 kind, const unsigned char *match) {
    struct deny_event *e = bpf_ringbuf_reserve(&deny_events, sizeof(*e), 0);
    if (!e) return 0;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    struct task_struct *t = (struct task_struct *)bpf_get_current_task();
    e->ppid = BPF_CORE_READ(t, real_parent, tgid);
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    e->hook = kind;
    __builtin_memcpy(e->match, match, POLICY_VALUE_LEN);
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static __always_inline int check_path(__u32 kind, const char *src_path, int from_kernel) {
    __u32 zero = 0;
    struct policy_key *k = bpf_map_lookup_elem(&scratch_key, &zero);
    if (!k) return 0;
    k->kind = kind;
    if (from_kernel) {
        bpf_probe_read_kernel_str(k->value, POLICY_VALUE_LEN, src_path);
    } else {
        bpf_probe_read_user_str(k->value, POLICY_VALUE_LEN, src_path);
    }
    struct policy_val *v = bpf_map_lookup_elem(&policy_map, k);
    if (v && (v->expires_ns == 0 || v->expires_ns > now_ns())) {
        emit_deny(kind, k->value);
        return -1;
    }
    return 0;
}

SEC("lsm/file_open")
int BPF_PROG(check_file_open, struct file *file) {
    if (!file) return 0;
    struct dentry *d = BPF_CORE_READ(file, f_path.dentry);
    if (!d) return 0;
    const unsigned char *name = BPF_CORE_READ(d, d_name.name);
    if (!name) return 0;
    return check_path(1 /* open_path */, (const char *)name, 1);
}

SEC("lsm/bprm_check_security")
int BPF_PROG(check_bprm, struct linux_binprm *bprm) {
    const char *fname = BPF_CORE_READ(bprm, filename);
    if (!fname) return 0;
    return check_path(0 /* exec_path */, fname, 1);
}

SEC("lsm/socket_connect")
int BPF_PROG(check_socket_connect, struct socket *sock,
             struct sockaddr *address, int addrlen) {
    if (!address) return 0;
    sa_family_t fam = BPF_CORE_READ(address, sa_family);
    if (fam != AF_INET) return 0;
    struct sockaddr_in *sin = (struct sockaddr_in *)address;
    __u32 daddr = BPF_CORE_READ(sin, sin_addr.s_addr);
    __u32 zero = 0;
    struct policy_key *k = bpf_map_lookup_elem(&scratch_key, &zero);
    if (!k) return 0;
    __builtin_memset(k, 0, sizeof(*k));
    k->kind = 2;
    __builtin_memcpy(k->value, &daddr, sizeof(daddr));
    struct policy_val *v = bpf_map_lookup_elem(&policy_map, k);
    if (v && (v->expires_ns == 0 || v->expires_ns > now_ns())) {
        emit_deny(2, k->value);
        return -1;
    }
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
