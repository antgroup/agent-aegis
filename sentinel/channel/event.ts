import { randomUUID } from "node:crypto";
import {
  EVENT_SCHEMA_VERSION,
  type ProbeEventSource,
  type VerdictAction,
  type VerdictSeverity,
} from "./schema.js";

/**
 * Process identity + lineage for the PID that produced an event (v2/M10).
 * Populated best-effort by the probe layer; every field is optional because a
 * source may not have it (e.g. a process that exited before enrichment).
 */
export interface ProcessInfo {
  /** Thread id (kernel TID); equals pid for single-threaded callers. */
  tid?: number;
  /** Parent pid. Canonical source for the native judge's process-tree checks. */
  ppid?: number;
  /** Process group id. */
  pgid?: number;
  /** Session id. */
  sid?: number;
  /** Real user id. */
  uid?: number;
  /** Real group id. */
  gid?: number;
  /** Short command name (comm, 16 chars). */
  comm?: string;
  /** Resolved executable path (`/proc/<pid>/exe`). */
  exe?: string;
  /** Working directory (`/proc/<pid>/cwd`). */
  cwd?: string;
  /** Full argument vector (richer than comm). */
  cmdline?: string[];
  /** Process start time (kernel clock ticks); pairs with pid to survive pid reuse. */
  startTime?: number;
  /** Ancestor pid chain (pid → ppid → …), bounded; first entry is the direct parent. */
  ancestors?: number[];
}

/** Container / namespace context (v2/M10). Needed to scope a containerized agent. */
export interface ContainerInfo {
  /** cgroup v2 path or v1 controller path. */
  cgroup?: string;
  /** Numeric cgroup id when available. */
  cgroupId?: number;
  pidNs?: number;
  netNs?: number;
  mntNs?: number;
}

/** Structured connection info for network syscalls (v2/M10). */
export interface NetInfo {
  family?: string;
  proto?: string;
  daddr?: string;
  dport?: number;
  saddr?: string;
  sport?: number;
}

export interface ProbeEvent {
  /** Schema version this event was emitted under. */
  schema: number;
  /** Globally unique event id. */
  id: string;
  /** Epoch milliseconds when the probe captured the event. */
  timestamp: number;
  /** Which probe or layer produced this event. */
  source: ProbeEventSource;
  /** Syscall or hook name (e.g. "execve", "openat", "tool_call"). */
  syscall: string;
  /** PID that produced the event (or 0 if not process-bound). */
  pid: number;
  /** Captured arguments. Probe-specific shape; judges should defensively narrow. */
  args: Record<string, unknown>;
  /** Optional session identifier from the agent runtime. */
  sessionKey?: string;
  /** Optional run/turn identifier from the agent runtime. */
  runId?: string;
  /** Optional tool name when the event happens inside a tool call. */
  toolName?: string;
  /** Process identity + lineage (v2). Best-effort; supersedes `meta.ppid`/`meta.comm`. */
  proc?: ProcessInfo;
  /** Container / namespace context (v2). */
  container?: ContainerInfo;
  /** Structured connection info for network syscalls (v2). */
  net?: NetInfo;
  /** Event that causally precedes this one (set by the attribution engine, P2). */
  parentEventId?: string;
  /** Correlation id linking events of one logical action (e.g. a tool call + its syscalls). */
  correlationId?: string;
  /** Free-form metadata passed through by the probe; sentinel does not interpret it. */
  meta?: Record<string, unknown>;
}

export type VerdictSideEffect =
  | { kind: "log"; level: "warn" | "error"; message: string }
  | { kind: "notify_user"; message: string }
  | { kind: "terminate_process"; pid: number };

export interface Verdict {
  /** Decision: allow lets execution continue, observe records only, block stops execution. */
  action: VerdictAction;
  /** Severity for logging / UI ranking. */
  severity: VerdictSeverity;
  /** Human-readable reason; shown to operators and (when appropriate) to the agent. */
  reason: string;
  /** Identifier of the judge that produced this verdict. */
  judgeId: string;
  /** 0..1 confidence; non-deterministic judges should report < 1. */
  confidence: number;
  /** Optional side effects the runtime may apply if its capabilities allow. */
  sideEffects?: VerdictSideEffect[];
}

export interface AggregatedVerdict {
  /** Final verdict after aggregation. */
  final: Verdict;
  /** All individual verdicts that participated (for audit / cloud sync). */
  sources: Verdict[];
}

export function createProbeEvent(
  input: Omit<ProbeEvent, "schema" | "id" | "timestamp"> &
    Partial<Pick<ProbeEvent, "id" | "timestamp">>,
): ProbeEvent {
  return {
    schema: EVENT_SCHEMA_VERSION,
    id: input.id ?? randomUUID(),
    timestamp: input.timestamp ?? Date.now(),
    source: input.source,
    syscall: input.syscall,
    pid: input.pid,
    args: input.args,
    sessionKey: input.sessionKey,
    runId: input.runId,
    toolName: input.toolName,
    proc: input.proc,
    container: input.container,
    net: input.net,
    parentEventId: input.parentEventId,
    correlationId: input.correlationId,
    meta: input.meta,
  };
}
