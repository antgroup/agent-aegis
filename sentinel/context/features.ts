import type { BufferedEvent } from "./buffer.js";
import { SENSITIVE_PATTERNS, isExternalAddr } from "./patterns.js";

/**
 * Numeric behavioral features extracted from a session's event buffer.
 *
 * These form a compact feature vector that both rule-based judges and
 * AI prompts can consume. Pure function — no side effects, no state.
 */
export interface BehavioralFeatures {
  /** Forks per minute within the buffer window. */
  forkRate: number;
  /** Number of unique binary paths seen in execve events. */
  uniqueBinaries: number;
  /** Count of openat calls matching sensitive path patterns. */
  sensitivePathHitCount: number;
  /** Count of connect calls to external (non-private) addresses. */
  externalConnCount: number;
  /** Number of distinct child PIDs spawned from agent processes. */
  processFanout: number;
  /** Count of tool_call events. */
  toolCallCount: number;
  /** Average interval in ms between tool_call events (0 if <2 tool calls). */
  avgToolCallInterval: number;
  /** Ratio of external-attribution events to total events (0..1). */
  externalEventRatio: number;
  /** Number of distinct unique PIDs observed. */
  uniquePidCount: number;
  /** Number of events with causalFlags set. */
  flaggedEventCount: number;
}

/**
 * Extract numeric behavioral features from a session's event buffer.
 * Single pass O(n) computation.
 */
export function extractFeatures(events: BufferedEvent[]): BehavioralFeatures {
  if (events.length === 0) {
    return {
      forkRate: 0,
      uniqueBinaries: 0,
      sensitivePathHitCount: 0,
      externalConnCount: 0,
      processFanout: 0,
      toolCallCount: 0,
      avgToolCallInterval: 0,
      externalEventRatio: 0,
      uniquePidCount: 0,
      flaggedEventCount: 0,
    };
  }

  const pids = new Set<number>();
  const binaries = new Set<string>();
  const agentChildPids = new Set<number>();
  let forkCount = 0;
  let sensitivePaths = 0;
  let externalConns = 0;
  let toolCallCount = 0;
  let externalCount = 0;
  let flaggedCount = 0;
  const toolCallTimestamps: number[] = [];

  const earliest = events[0].timestamp;
  const latest = events[events.length - 1].timestamp;
  const windowMinutes = Math.max((latest - earliest) / 60_000, 1 / 60_000); // avoid div/0

  for (const ev of events) {
    pids.add(ev.pid);

    // Attribution counting
    if (ev.attribution === "external") externalCount++;

    // Fork rate
    if (ev.syscall === "fork") {
      forkCount++;
      // Track agent-spawned children
      if (ev.attribution === "agent" || ev.attribution === "descendant") {
        agentChildPids.add(ev.pid);
      }
    }

    // Tool calls
    if (ev.syscall === "tool_call") {
      toolCallCount++;
      toolCallTimestamps.push(ev.timestamp);
    }

    // Unique binaries from execve
    if (ev.syscall === "execve" && ev.exe) {
      binaries.add(ev.exe);
    }

    // Sensitive path access
    if (ev.syscall === "openat" && ev.argsSummary) {
      if (SENSITIVE_PATTERNS.some((p) => p.test(ev.argsSummary!))) {
        sensitivePaths++;
      }
    }

    // External connections
    if (ev.syscall === "connect" && ev.destAddr) {
      if (isExternalAddr(ev.destAddr)) {
        externalConns++;
      }
    }

    // Flagged events
    if (ev.causalFlags && ev.causalFlags.length > 0) {
      flaggedCount++;
    }
  }

  // Average tool call interval
  let avgToolCallInterval = 0;
  if (toolCallTimestamps.length >= 2) {
    let totalInterval = 0;
    for (let i = 1; i < toolCallTimestamps.length; i++) {
      totalInterval += toolCallTimestamps[i] - toolCallTimestamps[i - 1];
    }
    avgToolCallInterval = totalInterval / (toolCallTimestamps.length - 1);
  }

  return {
    forkRate: forkCount / windowMinutes,
    uniqueBinaries: binaries.size,
    sensitivePathHitCount: sensitivePaths,
    externalConnCount: externalConns,
    processFanout: agentChildPids.size,
    toolCallCount,
    avgToolCallInterval,
    externalEventRatio: events.length > 0 ? externalCount / events.length : 0,
    uniquePidCount: pids.size,
    flaggedEventCount: flaggedCount,
  };
}