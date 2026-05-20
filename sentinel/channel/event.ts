import { randomUUID } from "node:crypto";
import {
  EVENT_SCHEMA_VERSION,
  type ProbeEventSource,
  type VerdictAction,
  type VerdictSeverity,
} from "./schema.js";

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
    meta: input.meta,
  };
}
