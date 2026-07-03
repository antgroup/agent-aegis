import type { BufferedEvent } from "./buffer.js";
import { SENSITIVE_PATTERNS, isExternalAddr } from "./patterns.js";
import { extractFeatures, type BehavioralFeatures } from "./features.js";

/**
 * BehavioralSnapshot is a structured summary of a session's recent behavior.
 * It is the primary data structure that AI prompts and rule judges consume.
 *
 * Built from a SessionEventBuffer by a single-pass scan.
 */

export interface BehavioralSnapshot {
  /** Session key this snapshot describes. */
  sessionKey: string;
  /** Time range covered. */
  earliestTimestamp: number;
  latestTimestamp: number;
  eventCount: number;

  /** Distinct tool names called (from tool_call / l1-hook events). */
  toolsCalled: string[];
  /** Distinct binary paths executed (from execve events). */
  binariesExecuted: string[];
  /** Sensitive paths accessed (from openat to known-sensitive patterns). */
  sensitiveAccesses: string[];
  /** External network connections initiated (from connect to non-private addrs). */
  externalConnections: Array<{ addr: string; port?: number }>;
  /** Causal chain flags aggregated across all events in the buffer. */
  causalChains: string[];
  /** Attribution breakdown: counts of agent/descendant/external events. */
  attributionCounts: { agent: number; descendant: number; external: number; unknown: number };
  /** Numeric feature vector. */
  features: BehavioralFeatures;
  /** Most recent N events, summarized as one-line strings (for prompt inclusion). */
  recentEventsSummary: string[];
}

/** Default number of recent events to include in the summary. */
const DEFAULT_RECENT_SUMMARY_COUNT = 30;

/**
 * Build a BehavioralSnapshot from a session's buffered events.
 * Single-pass scan: O(n) time, O(k) additional space for the summary lists.
 */
export function buildSnapshot(
  events: BufferedEvent[],
  sessionKey: string,
  recentCount: number = DEFAULT_RECENT_SUMMARY_COUNT,
): BehavioralSnapshot {
  if (events.length === 0) {
    return {
      sessionKey,
      earliestTimestamp: 0,
      latestTimestamp: 0,
      eventCount: 0,
      toolsCalled: [],
      binariesExecuted: [],
      sensitiveAccesses: [],
      externalConnections: [],
      causalChains: [],
      attributionCounts: { agent: 0, descendant: 0, external: 0, unknown: 0 },
      features: extractFeatures(events),
      recentEventsSummary: [],
    };
  }

  const toolsCalledSet = new Set<string>();
  const binariesSet = new Set<string>();
  const sensitiveSet = new Set<string>();
  const externalConns: Array<{ addr: string; port?: number }> = [];
  const causalChainsSet = new Set<string>();
  const attrCounts = { agent: 0, descendant: 0, external: 0, unknown: 0 };

  for (const ev of events) {
    // Attribution
    if (ev.attribution === "agent") attrCounts.agent++;
    else if (ev.attribution === "descendant") attrCounts.descendant++;
    else if (ev.attribution === "external") attrCounts.external++;
    else attrCounts.unknown++;

    // Tool calls
    if (ev.syscall === "tool_call" && ev.toolName) {
      toolsCalledSet.add(ev.toolName);
    }

    // Executed binaries
    if (ev.syscall === "execve" && ev.exe) {
      binariesSet.add(ev.exe);
    }

    // Sensitive path access
    if (ev.syscall === "openat" && ev.argsSummary) {
      if (SENSITIVE_PATTERNS.some((p) => p.test(ev.argsSummary!))) {
        sensitiveSet.add(ev.argsSummary);
      }
    }

    // External connections
    if (ev.syscall === "connect" && ev.destAddr) {
      if (isExternalAddr(ev.destAddr)) {
        externalConns.push({ addr: ev.destAddr, port: ev.destPort });
      }
    }

    // Causal chains
    if (ev.causalFlags) {
      for (const flag of ev.causalFlags) {
        causalChainsSet.add(flag);
      }
    }
  }

  // Deduplicate external connections (same addr:port seen multiple times)
  const seenConns = new Set<string>();
  const dedupedConns = externalConns.filter((c) => {
    const key = `${c.addr}:${c.port ?? 0}`;
    if (seenConns.has(key)) return false;
    seenConns.add(key);
    return true;
  });

  // Recent events summary: last N events as one-line strings.
  const recentStart = Math.max(0, events.length - recentCount);
  const recentEventsSummary: string[] = [];
  for (let i = recentStart; i < events.length; i++) {
    recentEventsSummary.push(summarizeEvent(events[i]));
  }

  return {
    sessionKey,
    earliestTimestamp: events[0].timestamp,
    latestTimestamp: events[events.length - 1].timestamp,
    eventCount: events.length,
    toolsCalled: [...toolsCalledSet],
    binariesExecuted: [...binariesSet],
    sensitiveAccesses: [...sensitiveSet],
    externalConnections: dedupedConns,
    causalChains: [...causalChainsSet],
    attributionCounts: attrCounts,
    features: extractFeatures(events),
    recentEventsSummary,
  };
}

/**
 * Render a BufferedEvent into a one-line human-readable summary.
 * Format: `[HH:MM:SS] syscall argsSummary (pid=N, attr=...)`
 */
export function summarizeEvent(e: BufferedEvent): string {
  const ts = new Date(e.timestamp);
  const time = `${pad(ts.getHours())}:${pad(ts.getMinutes())}:${pad(ts.getSeconds())}`;
  let detail = e.argsSummary ?? "";
  if (e.syscall === "tool_call" && e.toolName) {
    detail = e.toolName;
  } else if (e.syscall === "connect" && e.destAddr) {
    detail = `${e.destAddr}${e.destPort ? `:${e.destPort}` : ""}`;
  }
  const attr = e.attribution ?? "?";
  const causal = e.causalFlags?.length ? ` flags=[${e.causalFlags.join(",")}]` : "";
  const correl = e.correlationId ? ` corr=${e.correlationId.substring(0, 8)}` : "";
  return `[${time}] ${e.syscall}${detail ? ` ${detail}` : ""} (pid=${e.pid}, attr=${attr}${causal}${correl})`;
}

function pad(n: number): string {
  return n < 10 ? `0${n}` : `${n}`;
}