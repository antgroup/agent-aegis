/**
 * Schema version of probe events.
 *
 * Bumped when ProbeEvent / Verdict field semantics change in a way that
 * downstream consumers (cloud collaboration, LLM judges, archived logs)
 * cannot ignore. Additive changes do not require a bump.
 */
export const EVENT_SCHEMA_VERSION = 1;

export type ProbeEventSource = "ebpf" | "uprobe" | "lsm" | "l1-hook" | "test";

export type VerdictAction = "allow" | "observe" | "block";

export type VerdictSeverity = "info" | "low" | "medium" | "high" | "critical";

export type AggregatorStrategy = "strictest" | "weighted";
