/**
 * Schema version of probe events.
 *
 * Bumped when ProbeEvent / Verdict field semantics change in a way that
 * downstream consumers (cloud collaboration, LLM judges, archived logs)
 * cannot ignore. Additive changes do not require a bump.
 */
export const EVENT_SCHEMA_VERSION = 1;
