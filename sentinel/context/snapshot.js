import { SENSITIVE_PATTERNS, isExternalAddr } from "./patterns.js";
import { extractFeatures } from "./features.js";
/** Default number of recent events to include in the summary. */
const DEFAULT_RECENT_SUMMARY_COUNT = 30;
/**
 * Build a BehavioralSnapshot from a session's buffered events.
 * Single-pass scan: O(n) time, O(k) additional space for the summary lists.
 */
export function buildSnapshot(events, sessionKey, recentCount = DEFAULT_RECENT_SUMMARY_COUNT) {
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
    const toolsCalledSet = new Set();
    const binariesSet = new Set();
    const sensitiveSet = new Set();
    const externalConns = [];
    const causalChainsSet = new Set();
    const attrCounts = { agent: 0, descendant: 0, external: 0, unknown: 0 };
    for (const ev of events) {
        // Attribution
        if (ev.attribution === "agent")
            attrCounts.agent++;
        else if (ev.attribution === "descendant")
            attrCounts.descendant++;
        else if (ev.attribution === "external")
            attrCounts.external++;
        else
            attrCounts.unknown++;
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
            if (SENSITIVE_PATTERNS.some((p) => p.test(ev.argsSummary))) {
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
    const seenConns = new Set();
    const dedupedConns = externalConns.filter((c) => {
        const key = `${c.addr}:${c.port ?? 0}`;
        if (seenConns.has(key))
            return false;
        seenConns.add(key);
        return true;
    });
    // Recent events summary: last N events as one-line strings.
    const recentStart = Math.max(0, events.length - recentCount);
    const recentEventsSummary = [];
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
export function summarizeEvent(e) {
    const ts = new Date(e.timestamp);
    const time = `${pad(ts.getHours())}:${pad(ts.getMinutes())}:${pad(ts.getSeconds())}`;
    let detail = e.argsSummary ?? "";
    if (e.syscall === "tool_call" && e.toolName) {
        detail = e.toolName;
    }
    else if (e.syscall === "connect" && e.destAddr) {
        detail = `${e.destAddr}${e.destPort ? `:${e.destPort}` : ""}`;
    }
    const attr = e.attribution ?? "?";
    const causal = e.causalFlags?.length ? ` flags=[${e.causalFlags.join(",")}]` : "";
    const correl = e.correlationId ? ` corr=${e.correlationId.substring(0, 8)}` : "";
    return `[${time}] ${e.syscall}${detail ? ` ${detail}` : ""} (pid=${e.pid}, attr=${attr}${causal}${correl})`;
}
function pad(n) {
    return n < 10 ? `0${n}` : `${n}`;
}
