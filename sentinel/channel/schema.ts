/**
 * Schema version of probe events.
 *
 * Bumped when ProbeEvent / Verdict field semantics change in a way that
 * downstream consumers (cloud collaboration, LLM judges, archived logs)
 * cannot ignore. Additive changes do not require a bump.
 *
 * v2 (M10): added optional, additive enrichment fields to ProbeEvent —
 * `proc` (process identity + lineage), `container` (cgroup / namespaces),
 * `net` (structured connection info), and the `parentEventId` / `correlationId`
 * causal slots. All are optional and back-compatible; a v1 consumer that ignores
 * them keeps working. The bump is informational: it tells consumers "this event
 * MAY carry the richer attribution context".
 */
export const EVENT_SCHEMA_VERSION = 2;

export type ProbeEventSource = "ebpf" | "uprobe" | "lsm" | "l1-hook" | "test";

export type VerdictAction = "allow" | "observe" | "block";

export type VerdictSeverity = "info" | "low" | "medium" | "high" | "critical";

export type AggregatorStrategy = "strictest" | "weighted";
