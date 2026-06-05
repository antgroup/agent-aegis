# LSM probe (enforce)

Kernel-level enforcement layer for the sentinel pipeline (M7.5).

Unlike the eBPF tracepoint (M5) and uprobe (M7) probes which are
observe-only, this probe **denies** syscalls in-kernel via eBPF LSM hooks.
It does not produce general-purpose syscall events on its own — its event
stream is restricted to `kind: "deny"` records that say "this syscall was
just blocked by policy entry X."

## Threat model fit

The aggregator's `strictest` strategy produces high-severity `block`
verdicts on the **first** occurrence of a violating syscall (e.g. `cat
/etc/shadow`). Policy is eventually consistent: the first attempt is
observed, the entry is pushed to the BPF `policy_map`, and the **second**
attempt is denied directly inside the LSM hook with `-EPERM`.

This is the explicit trade-off vs. synchronous user-space blocking:
P99 stays well under 50 μs and there is no fail-open window from a
user-space timeout.

## When this runs

```yaml
probes:
  lsm:
    enabled: true
    policyTtlSeconds: 3600     # how long a policy entry stays installed
    maxEntries: 1024           # BPF map capacity; LRU evicts oldest
    minSeverity: high          # only block / high+ verdicts become policy
```

## Requirements

| Component | Requirement |
|---|---|
| OS | Linux ≥ 5.7 |
| Kernel | `CONFIG_BPF_LSM=y` + `bpf` listed in `/sys/kernel/security/lsm` (set via kernel cmdline `lsm=...,bpf` or sysctl `kernel.lsm`) |
| Privileges | `CAP_BPF` + `CAP_PERFMON` (or root) |
| Build tools | `clang`, `llvm-strip`, `bpftool`, `go ≥ 1.22` — only needed when building the runner from source |

Verify support:

```bash
cat /sys/kernel/security/lsm   # must contain `bpf`
```

## Runner binary

Compiled Go binary at `runner/dist/lsm-runner`:

```bash
cd sentinel/probes/lsm/runner
make vmlinux                   # generate bpf/vmlinux.h from running kernel
make                           # builds bpf/lsm.bpf.o, then dist/lsm-runner
```

The Go binary embeds `lsm.bpf.o` via `go:embed`, so the runner ships as a
single static ELF. CO-RE BTF relocations let the same binary run on any
≥ 5.7 kernel with vmlinux BTF.

## Wire protocol

Node → runner (stdin, one JSON per line):

```jsonl
{"kind":"policy_upsert","entry":{"kind":"open_path","value":"/etc/shadow","severity":"critical","expiresAt":1700003600000,"source":"native:sensitive-path"}}
{"kind":"policy_clear"}
```

runner → Node (stdout, one JSON per line):

```jsonl
{"kind":"ready","hooks":["file_open","bprm_check_security","socket_connect"]}
{"kind":"deny","hook":"file_open","pid":1234,"ppid":1,"comm":"cat","match":"/etc/shadow","ts":1700000000000}
{"kind":"log","level":"warn","message":"…"}
```

## Why exec_path / open_path / connect_addr

The three policy kinds correspond to the LSM hooks attached:

| Policy kind | Hook | Matches |
|---|---|---|
| `exec_path` | `bprm_check_security` | `execve` filename prefix |
| `open_path` | `file_open` | path passed to `open` / `openat` |
| `connect_addr` | `socket_connect` | IPv4 daddr exact match |

When `judge.action === "block"` with severity ≥ `minSeverity`, the loader
parses the verdict's `reason` field for `path=...` or `addr=...` and
inserts the matching policy entry. The native judge in M2/M5 was updated
in M7.5 to include these structured suffixes in `reason`.

## End-to-end verification

```bash
npm run build
cd sentinel/probes/lsm/runner && make    # build runner inside container
npm run e2e:lsm
```

The wrapper builds the sibling Dockerfile and runs `verify-e2e.mjs`. The
test:

1. Starts sentinel with native judge + LSM probe.
2. `cat /etc/shadow` once — verdict fires, policy entry inserted.
3. `cat /etc/shadow` again — kernel returns `Permission denied` before
   `/etc/shadow` is even opened. A `deny` runner event is emitted and
   reflected as a `source: "lsm"` ProbeEvent in the JSONL log.

Non-zero exit means either the first verdict didn't fire or the second
attempt wasn't denied.

## Scope reminder

M7.5 supports:
- Exact path match (no glob / regex inside the kernel)
- IPv4 exact match for `connect_addr` (no CIDR / IPv6 yet)
- System-wide policy (no per-cgroup / namespace scoping)

Pattern expansion and namespace scoping are deferred — M7.5 keeps the BPF
program small enough to stay safely under the verifier's complexity limit
on older kernels.
