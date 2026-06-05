# Uprobe probe

User-space symbol tracer for the sentinel pipeline (M7, observe-only).

Unlike the eBPF tracepoint probe (M5) which hooks syscall entries in the
kernel, this probe attaches **uprobes** on libc (and optionally libssl)
symbols. That gives it two advantages over tracepoints:

- It sees parameters as the application passed them to libc (e.g. the path
  argument to `openat` even when an interposed `LD_PRELOAD` rewrites it
  later).
- It can hook `SSL_write` / `SSL_read` — observing plaintext **before**
  encryption, which tracepoints on `sendto` no longer recover.

It runs on Linux only and ships as an opt-in BCC Python child process,
identical operational model to the eBPF tracepoint probe.

## When this runs

```yaml
probes:
  uprobe:
    enabled: true
    libcPath: /lib/x86_64-linux-gnu/libc.so.6   # optional; auto-detected on common distros
    opensslPath: /lib/x86_64-linux-gnu/libssl.so.3  # optional; required for SSL_* targets
    targets: [execve, openat, connect]          # default subset; add SSL_write / SSL_read explicitly
```

With the default config the loader is silent — sentinel keeps running
with whatever other probes are active.

## Requirements

| Component | Requirement |
|---|---|
| OS | Linux. Other platforms early-return via `detectUprobeSupport`. |
| Privileges | Root (or `CAP_BPF` + `CAP_PERFMON` on 5.8+) — uprobes use the same kernel facility as kprobes. |
| Userspace | `python3` + `bcc` (Debian: `apt install bpfcc-tools python3-bpfcc`). |
| Target binaries | Symbols must be exported (libc / libssl are by default). |

Uprobes do **not** need `CAP_SYS_PTRACE` — the kernel rewrites the target
binary's text at attach time via its own uprobe subsystem, not via ptrace.
This is the key production advantage over Frida.

## Wire protocol

JSONL on stdout, byte-compatible with the eBPF runner save for the
`source: "uprobe"` field stamped by the loader:

```jsonl
{"kind":"ready","probes":["execve","openat","connect"]}
{"kind":"syscall","syscall":"execve","pid":1234,"ppid":1,"ts":1700000000000,"path":"/bin/cat","argv":["/bin/cat","/etc/shadow"]}
{"kind":"syscall","syscall":"SSL_write","pid":1234,"ts":...,"preview":"GET /api/keys HTTP/1.1\r\n...","extra":{"size":1024}}
```

## End-to-end verification

```bash
npm run build
npm run e2e:uprobe
```

This builds the sibling `Dockerfile` and runs `verify-e2e.mjs` inside a
privileged container. Triggers `cat /etc/shadow` and asserts the native
judge produces a critical block verdict, just like the eBPF e2e but with
events coming from `source: "uprobe"`.

## Coverage compared to other probes

| Symbol | uprobe sees | tracepoint sees | LSM sees |
|---|---|---|---|
| `execve` | filename + argv at libc entry | post-glibc syscall entry | yes, can deny |
| `openat` | path as passed to libc | as passed to kernel | yes, can deny |
| `connect` | sockaddr pointer | sockaddr at syscall entry | yes, can deny |
| `SSL_write` / `SSL_read` | **plaintext + size** | encrypted bytes | n/a |

For maximum visibility, run uprobe + ebpf tracepoint side by side.
Aggregator's `strictest` strategy handles the duplicate events without
special-casing.
