# Sentinel Roadmap — from eBPF probes to system-level response

> Branch: `sentinel-response` (off `eBPF`). This document is the north star for
> evolving the kernel layer from a passive observer into the sensing substrate
> that *drives* system-level protection.

## Vision

eBPF probes are the **sensing layer**. They must feed a structured, *attributable*
event substrate that detection and response build on. The end state: kernel
events drive graduated, system-level enforcement (in-kernel deny, process kill,
network / filesystem isolation) — not just per-syscall logging.

The arc, in order of dependency:

```
capture → attribute → correlate → detect → respond → operate
  P1         P2          P2         P3        P4        P5
```

We start at **capture & organization** (this milestone), because every later
phase is only as good as the event stream underneath it.

## Current state (baseline — what exists today)

- **Probes**: eBPF tracepoints `sys_enter_{execve,openat,connect}`, plus uprobe
  and LSM probes. The BCC runner emits one JSON line per event.
- **Per-event fields captured now**: `syscall, pid, ppid, comm, ts` + `argv`
  (execve) / `path` (openat) / `addr` (connect). (`probes/ebpf/messages.ts`,
  `runner/probe.py`.)
- **Normalized event**: `ProbeEvent { schema, id, ts, source, syscall, pid, args,
  sessionKey?, runId?, toolName?, meta? }` (`channel/event.ts`).
- **Pipeline**: probe → bus → judges (`l1-bridge`, `native`) → aggregator →
  `AggregatedVerdict` → `ProbeEventStore` (daily JSONL) + `onSentinelEvent` →
  WebUI (`channel/webui-bridge.ts`).
- **Response today**: verdict `action ∈ {allow, observe, block}`; `sideEffects`
  typed as `log | notify_user | terminate_process`, but only LSM-BPF performs a
  real in-kernel block. tracepoints are observe-only.
- **Store today**: append-only JSONL with daily UTC rotation under
  `<stateDir>/probe-events/events-YYYY-MM-DD.jsonl`; events and verdicts share
  one stream (`kind` discriminator).

### Known gaps (these set the agenda)

1. **Attribution is a placeholder.** `native.ts` has `agentPids` +
   `process-tree-anomaly`, but it is the M5 stub: only the agent **main** PID is
   reliably known. There is no live fork/clone tracking that grows the descendant
   set, so "is this syscall from the agent's process tree?" is unreliable.
2. **System-wide capture = noise.** Probes see every process, agent-related or
   not, with no first-class agent/not-agent tag.
3. **No cross-event correlation.** Judges reason about single syscalls; there is
   no notion of a chain (write-then-exec, read-secret-then-connect) spanning
   processes.
4. **Store is a flat log, not queryable.** No index for "what did this session's
   process tree do at the kernel level."

## Phase 1 — Event capture & organization  *(this milestone — start here)*

**Goal:** turn raw probe output into a clean, rich, attribution-ready, queryable
event substrate.

- **1.1 Enrich `ProbeEvent` (bump `EVENT_SCHEMA_VERSION`, keep back-compat parse):**
  - identity: `tid, pgid, sid, uid, gid, exe, cwd, start_time, cmdline`.
  - lineage: `ppid` + ancestor chain captured at event time.
  - container: `cgroup_id`/path, namespace ids (pid/net/mnt) for containerized agents.
  - net: for `connect`, structured `family/proto/daddr/dport` (not just a string).
  - causal slots: keep `id`; reserve `parentEventId` / `correlationId` for Phase 2.
- **1.2 Capture process-lifecycle syscalls** so the tree can be maintained:
  add `sched_process_{fork,exec,exit}` tracepoints (cheaper + race-free vs
  `sys_enter_clone`); extend the `EbpfMessage` wire protocol with the new kinds.
  *This is the raw material the attribution engine (P2) needs.*
- **1.3 Organize storage:** keep JSONL as the durable log, add a **queryable
  index** (SQLite WAL, or in-memory ring + periodic flush) keyed by
  `(ts, pid, session, syscall, attribution)`; retention + size caps;
  **redact secrets** in `argv`/`path` before persisting; expose a read API
  (query by session / run / pid / time-range).
- **1.4 Backpressure:** bounded probe→bus queue; under flood, sample/drop with a
  counted `dropped=N` marker — never silent loss.

**Deliverable:** every probe event lands enriched and queryable; the WebUI can
render a per-session **kernel timeline**.

## Phase 2 — Attribution & correlation engine

**Goal:** answer "did the agent cause this?" precisely, and stitch kernel events
to agent actions.

- **2.1 Live agent subtree:** seed with the agent/runtime PID; grow/shrink from
  fork/exit events. Tag every event `attribution ∈ {agent, descendant, unknown,
  external}` + owning `sessionKey`/`runId`.
- **2.2 Tool-call ↔ syscall correlation:** when L1 sees `exec`/`bash`, open a
  correlation window and tag the resulting `execve` + its descendants with that
  `runId`/`toolName` (extend the existing `l1-bridge` judge).
- **2.3 Causal chains:** link `read(secret) → connect(external)` (exfil) and
  `write(script) → exec(script)` (write-then-run) across the subtree.
- **2.4 Per-session timeline:** an ordered, queryable "what the agent's tree did
  in kernel space this run."

## Phase 3 — Behavioral detection on the organized stream

**Goal:** detect what single-syscall rules can't.

- sequence / graph rules over the correlated stream: exfil chains, lateral
  movement, privilege escalation, persistence (cron / systemd / `~/.ssh` writes).
- per-session baselining + anomaly scoring (unexpected binary, unusual egress,
  process fan-out).
- confidence-scored verdicts (schema already supports `confidence < 1` +
  multi-judge aggregation).

## Phase 4 — System-level response  *(the goal: probes DRIVE protection)*

**Goal:** verdicts drive graduated, system-level enforcement.

- **response ladder:** `observe → alert → throttle → block(LSM) → kill →
  isolate`.
- **mechanisms:** LSM-BPF in-kernel deny *(have it)*; process kill
  *(`terminate_process` sideEffect exists)*; egress cut (eBPF/tc/netfilter drop
  by `daddr`/`cgroup`); filesystem quarantine (deny writes to a path-set);
  cgroup freeze; seccomp tightening.
- **policy engine:** maps `(severity, attribution, confidence) → response` with
  safe defaults (never kill `unknown`/`external` processes), dry-run/observe
  rollout, and operator override.
- **fail-safe:** response failures fail-open + alert; never wedge the host.

## Phase 5 — Operations: visibility, audit, cloud, tuning

- **WebUI:** per-session kernel timeline, attribution graph, responses taken,
  one-click observe↔enforce.
- **audit/forensics:** queryable store → export, replay, post-incident timeline.
- **cloud sync:** ship `AggregatedVerdict.sources` for fleet correlation /
  threat intel (the schema already anticipates this).
- **tuning:** allowlists (known-good binaries / paths / egress), per-defense
  thresholds, noise budgets.

## Suggested sequencing (continuing the M-numbering)

| Milestone | Phase | Outcome |
|---|---|---|
| **M10** | P1 | enriched schema + lifecycle syscalls + queryable store *(this branch)* |
| M11 | P2 | live attribution + tool↔syscall correlation |
| M12 | P3 | behavioral / sequence detection |
| M13 | P4 | response ladder + policy engine |
| M14 | P5 | operator visibility, audit, cloud sync |

## Immediate next steps (Phase 1 kickoff)

1. Spec enriched `ProbeEvent` v2 (fields in 1.1); bump `EVENT_SCHEMA_VERSION`;
   keep the v1 parser back-compatible.
2. Add `sched_process_{fork,exec,exit}` to the BCC runner + new `EbpfMessage`
   kinds + loader handling.
3. Introduce an `EventStore` query layer (SQLite) beside the JSONL log;
   redact-on-write.
4. Add a per-session "kernel timeline" read API + a minimal WebUI view.
5. Tests: schema round-trip (v1+v2), lifecycle-event ingestion, attribution-set
   growth on fork/exit.

> Design rule carried over from sentinel: **fail-open everywhere** (a probe or
> store failure must never break the agent), and **observe-before-enforce** for
> every new response capability.
