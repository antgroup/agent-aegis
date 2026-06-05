# sentinel/

Framework-agnostic, low-level defense subsystem for ClawAegis.

This directory is the home of everything described in
`../../DEFENSE_TRANSITION_PLAN.md`: an event channel, a judge pipeline, and
probe + runtime adapters that lift the existing tool-call-level defenses to
the syscall layer (Frida, eBPF) without coupling them to any single agent
framework.

## Architecture in one screen

```
                   ┌─────────────────────────────────────────┐
                   │              SENTINEL CORE              │
                   │                                         │
[ebpf tracepoint]  │   ProbeEventBus → ProbeEventStore       │      ┌───────────────────┐
  (M5)         ────┼──► judges/    │  (JSONL daily-rotating) │──────►  L1 engine        │
                   │   Registry    │                         │      │  (src/engine.ts)  │
[uprobe]           │      ↓        │                         │      └───────────────────┘
  (M7)         ────┼──► aggregator(strictest|weighted) ──► onVerdict subscribers ──┐
                   │      ↓                                  │                     │
                   │   AggregatedVerdict → applyVerdict      │                     │
                   └────────────│────────────────────────────┘                     │
                                ↓                                                  │
                       AgentRuntime adapters                                       │
                       ┌──────────┬──────────┐                                     │
                       │ openclaw │  hermes  │                  [LSM enforce]      │
                       └──────────┴──────────┘                    (M7.5)  ◄────────┘
                                                              (kernel policy_map)
```

A unified Go libbpf runner (M8, `probes/lsm/runner/dist/sentinel-runner`)
handles all three eBPF modes via `--mode={ebpf,uprobe,lsm}`. The BCC Python
runners under `probes/{ebpf,uprobe}/runner/probe.py` remain as fallbacks
for early-dev environments without the toolchain to build the Go binary.

## Directory layout

```
sentinel/
├── channel/                Probe events + storage + pub-sub
│   ├── schema.ts           EVENT_SCHEMA_VERSION, action / severity enums
│   ├── event.ts            ProbeEvent, Verdict, AggregatedVerdict + factory
│   ├── store.ts            Append-only JSONL with UTC daily rotation
│   └── bus.ts              In-process pub-sub
├── judges/                 Decision logic
│   ├── base.ts             Judge interface + JudgeRegistry
│   ├── aggregator.ts       strictest | weighted strategies + runJudges()
│   ├── l1-bridge.ts        Wraps the L1 AegisDefenseEngine (structural)
│   └── native.ts           L2/L3 own rules: sensitive-path / kernel-escape /
│                           process-tree anomaly
├── probes/                 Syscall sources
│   ├── types.ts            Probe / ProbeDeps interface
│   ├── frida/              In-process userspace tracer (M4 + M4.5 enforce)
│   │   ├── agent.js        POSIX libc hook script
│   │   ├── agent-win.js    Windows placeholder
│   │   ├── platform.ts     detectFridaSupport()
│   │   ├── messages.ts     AgentMessage + parser
│   │   ├── loader.ts       createFridaProbe(opts) + enforce decision path
│   │   ├── index.ts        Re-exports
│   │   └── README.md       Deployment notes
│   └── ebpf/               Kernel-level tracer (M5, Linux only)
│       ├── runner/probe.py BCC tracepoints emitting JSONL
│       ├── platform.ts     detectEbpfSupport()
│       ├── messages.ts     EbpfMessage + parser
│       ├── loader.ts       createEbpfProbe(opts), Python subprocess
│       ├── index.ts        Re-exports
│       └── README.md       BCC / root / kernel requirements
├── runtime/                Agent framework abstraction
│   ├── types.ts            AgentRuntime contract
│   ├── noop-runtime.ts     For tests / isolated runs
│   └── adapters/
│       ├── openclaw.ts     OpenClaw plugin SDK adapter
│       └── hermes.ts       Hermes RPC-driven adapter (M6 draft)
├── __tests__/              Vitest suites (one file per concern)
├── index.ts                startSentinel(runtime) + SentinelHandle
└── README.md               You are here
```

## Dependency direction (hard rules)

| Layer | May import from |
|---|---|
| `channel/` | only `node:*` and own files |
| `runtime/types.ts` | only `channel/` types |
| `runtime/noop-runtime.ts` | only `runtime/types.ts` |
| `judges/*` (excluding `l1-bridge.ts`) | `channel/`, `judges/base.ts` |
| `judges/l1-bridge.ts` | declares L1 engine via **structural type only**, never imports `../src/*` |
| `probes/*` | `channel/`, `runtime/types.ts`, `probes/types.ts`, own files |
| `index.ts` | all of the above |
| `runtime/adapters/openclaw.ts` | additionally `runtime-api` (the framework SDK type) |
| `runtime/adapters/hermes.ts` | only sentinel types — no framework SDK |
| `ClawAegis/index.ts` (outside this dir) | adapter factories + judge factories + probe factories |

These rules are enforced by code review; the structural-type trick in
l1-bridge prevents the most common slippage automatically (a real `import`
would not type-check unless `../src/*` is in the include path, and a
follow-up PR or M7 will move sentinel core into its own `tsconfig` to make
this a build error).

## Milestone trace

| Milestone | Plan | Touched |
|---|---|---|
| M1 | `SENTINEL_M1_PLAN.md` | `channel/`, `judges/{base,aggregator}.ts`, `runtime/{types,noop-runtime}.ts`, `index.ts`, OpenClaw `index.ts` boot |
| M2 | `SENTINEL_M2_PLAN.md` | `judges/l1-bridge.ts`, `judges/native.ts` (slot scaffolding + sensitive-path) |
| M3 | `SENTINEL_M3_PLAN.md` | `runtime/adapters/openclaw.ts`, `src/handlers.ts` returns `engine` |
| M4 | `SENTINEL_M4_PLAN.md` | Frida probe + enforce path (historical — removed in M9) |
| M4.5 | `SENTINEL_M4_5_PLAN.md` | Frida enforce-mode (historical — removed in M9) |
| M5 | `SENTINEL_M5_PLAN.md` | `probes/ebpf/*`, `judges/native.ts` slots filled |
| M6 | `SENTINEL_M6_PLAN.md` | `runtime/adapters/hermes.ts`, this README |
| M7 | `SENTINEL_M7_PLAN.md` | `probes/uprobe/*` — libc symbol observer; replaces Frida observation |
| M7.5 | `SENTINEL_M7_5_PLAN.md` | `probes/lsm/*` — kernel LSM enforce; verdict→policy snapshot model; aggregator `onVerdict` |
| M8 | `SENTINEL_M8_PLAN.md` | `probes/lsm/runner/*` — unified Go libbpf CO-RE runner (`--mode={ebpf,uprobe,lsm}`) |
| M9 | `SENTINEL_M9_PLAN.md` | Frida deletion: `probes/frida/*` removed, `optionalDependencies.frida` dropped |

Every modification is contained inside the listed directories — earlier
milestone code is never edited beyond purely additive changes. If a
regression appears, the failing file path maps directly to a milestone.

## Adding things

- **A new judge** (cloud collaboration, LLM voting, custom rule pack):
  implement `Judge` from `judges/base.ts`, call `sentinel.registerJudge(j)`
  from `ClawAegis/index.ts`. No core changes needed.
- **A new probe** (e.g., Windows ETW, audit log replayer):
  implement `Probe` from `probes/types.ts`, register it via
  `sentinel.registerProbe(p)`. Probes live under their own subdirectory of
  `probes/`. Default OFF in OpenClaw config.
- **A new agent framework**:
  add `runtime/adapters/<framework>.ts`, return an `AgentRuntime`. Only
  framework-specific TS types may appear in that file.
- **Bumping the event format**:
  increment `EVENT_SCHEMA_VERSION` in `channel/schema.ts`; downstream
  consumers (audit log replays, cloud sync) read the field.

## Configuration surface (OpenClaw `userConfig.probes`)

```yaml
probes:
  ebpf:
    enabled: false             # M5, Linux only — syscall tracepoints
    pythonBin: /usr/bin/python3   # used when runnerScript runs the BCC fallback
    runnerScript: null            # null → bundled probes/ebpf/runner/probe.py
    runnerBin: null               # null → BCC path; else path to sentinel-runner
  uprobe:
    enabled: false             # M7, Linux only — libc / openssl symbol observer
    libcPath: null                # null → auto-detect common distro paths
    opensslPath: null             # required for SSL_write / SSL_read targets
    targets: [execve, openat, connect]
    pythonBin: /usr/bin/python3
    runnerScript: null
    runnerBin: null
  lsm:
    enabled: false             # M7.5, Linux ≥ 5.7 + CONFIG_BPF_LSM, in-kernel enforce
    minSeverity: high             # "high" | "critical"
    policyTtlSeconds: 3600
    maxEntries: 1024
    runnerBin: null               # null → probes/lsm/runner/dist/lsm-runner
```

Everything defaults OFF. Sentinel's bare-bones presence in OpenClaw without
any probe enabled is purely additive: it logs one `sentinel started: 0
probes, N judges` line and otherwise does nothing.

The legacy `probes.frida.*` block is accepted but no-op'd with a warn:
Frida support was removed in M9. Migrate to `probes.uprobe` for observation
and `probes.lsm` for enforcement.
