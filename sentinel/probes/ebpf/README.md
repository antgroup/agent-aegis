# eBPF probe

Kernel-level syscall tracer for the sentinel pipeline (M5, observe-only).

Unlike the Frida probe (M4) which is bound to the OpenClaw main process,
the eBPF probe sees syscalls **system-wide** — including any subprocess
that OpenClaw tools spawn. This is the layer where the native judge's
`judgeProcessTreeAnomaly` and `judgeKernelEscape` slots become actionable.

## When this runs

Opt-in via config and only on Linux:

```yaml
probes:
  ebpf:
    enabled: true
    pythonBin: /usr/bin/python3   # optional
    runnerScript: null            # optional; default uses bundled probe.py
```

The probe is a spawned Python child process running BCC. If `python3` is
missing, the `bcc` module is not installed, or kernel tracepoints fail to
attach, the loader logs a warn and returns — sentinel keeps running with
whatever other probes are active.

## Requirements

| Component | Requirement |
|---|---|
| OS | Linux. Other platforms early-return via `detectEbpfSupport`. |
| Kernel | Tracepoints `syscalls/sys_enter_execve`, `sys_enter_openat`, `sys_enter_connect`. Any kernel from ~4.x onwards works for this set. |
| Privileges | Root (or `CAP_BPF` + `CAP_PERFMON` on 5.8+). |
| Userspace | `python3` + `bcc` (Debian: `apt install bpfcc-tools python3-bpfcc`). |

## Wire protocol

The Python runner emits one JSON object per stdout line:

```jsonl
{"kind":"ready","probes":["execve","openat","connect"]}
{"kind":"syscall","syscall":"execve","pid":1234,"ppid":1,"ts":1700000000000,"path":"/bin/cat","comm":"bash"}
{"kind":"log","level":"warn","message":"…"}
```

`sentinel/probes/ebpf/messages.ts` parses these into `EbpfMessage` and the
loader translates `syscall` messages into `ProbeEvent`s.

## How this interacts with judges

- `judgeSensitivePath` (filled in M2) fires regardless of the event source —
  eBPF-sourced execve with argv `/etc/shadow` is blocked just like Frida's.
- `judgeProcessTreeAnomaly` (filled in M5) uses the `ppid` carried in
  `event.meta` to detect syscalls from processes outside the agent tree.
- `judgeKernelEscape` (filled in M5) flags execve of binaries launched from
  scratch directories (`/tmp`, `/dev/shm`, `/var/tmp`).

## End-to-end verification

A repeatable Linux-only smoke test lives next to the probe and proves the
full pipeline (probe → judge → verdict → JSONL):

```bash
npm run build          # ensure .js artifacts exist
npm run e2e:ebpf       # builds the Dockerfile here, runs verify-e2e.mjs
```

The wrapper script (`verify-e2e.sh`) builds the sibling `Dockerfile`,
mounts the repo into the container, and runs `verify-e2e.mjs`. The test
triggers `cat /etc/shadow` and asserts that the native judge produces a
critical block verdict; non-zero exit means a regression in the pipeline.
On macOS hosts you need Docker (OrbStack works) — eBPF cannot run on
darwin directly.

## Scope reminder

M5 is observe-only. Kernel-level enforce (LSM hooks) requires kernel 5.7+
and CO-RE; it's deferred to a separate milestone.
