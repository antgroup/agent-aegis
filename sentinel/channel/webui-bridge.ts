import fs from "node:fs";
import path from "node:path";
import type { AggregatedVerdict, ProbeEvent } from "./event.js";

/**
 * WebUI bridge.
 *
 * Forwards a sentinel event + aggregated verdict into the SAME
 * `defense-events.jsonl` that the L1 engine writes and the WebUI tails
 * (`web/api/src/services/file-watcher.ts`), so kernel-level (eBPF / uprobe /
 * LSM) detections appear on the Events page next to L1 tool-call defenses —
 * no WebUI code change required.
 *
 * The record matches the `RawDefenseEvent` shape `file-watcher.ts` parses.
 * `allow`/null verdicts are skipped: only real detections (block / observe)
 * are surfaced, so benign syscalls don't flood the UI.
 *
 * Dependency-direction note: this lives in `channel/` and imports only Node
 * built-ins + `./event.js`, never the L1 engine or runtime-api.
 */
export function appendWebuiDefenseEvent(
  eventsFile: string,
  event: ProbeEvent,
  verdict: AggregatedVerdict | null,
): void {
  if (!verdict) return;
  const action = verdict.final.action;
  const result: "blocked" | "observed" | null =
    action === "block" ? "blocked" : action === "observe" ? "observed" : null;
  if (!result) return; // allow → nothing to surface

  const record = {
    timestamp: event.timestamp,
    defense: verdict.final.judgeId,
    result,
    reason: verdict.final.reason,
    toolName: event.toolName,
    commandText: describeSyscall(event),
    details: {
      syscall: event.syscall,
      source: event.source,
      pid: event.pid,
      severity: verdict.final.severity,
      confidence: verdict.final.confidence,
    },
  };

  try {
    fs.mkdirSync(path.dirname(eventsFile), { recursive: true });
    fs.appendFileSync(eventsFile, JSON.stringify(record) + "\n", "utf8");
  } catch {
    // Best-effort: WebUI forwarding must never break the sentinel pipeline.
  }
}

/** Human-readable one-line summary of the syscall for the WebUI commandText column. */
function describeSyscall(event: ProbeEvent): string | undefined {
  const a = event.args ?? {};
  if (event.syscall === "execve") {
    const argv = Array.isArray(a.argv) ? a.argv.map(String).join(" ") : undefined;
    const launch = typeof a.path === "string" ? a.path : undefined;
    const body = argv ?? launch;
    return body ? `execve ${body}` : "execve";
  }
  if (event.syscall === "openat") {
    return typeof a.path === "string" ? `openat ${a.path}` : "openat";
  }
  if (event.syscall === "connect") {
    const dest =
      typeof a.dest === "string" ? a.dest : typeof a.addr === "string" ? a.addr : "";
    return dest ? `connect ${dest}` : "connect";
  }
  if (event.syscall === "tool_call") {
    return event.toolName ? `tool_call ${event.toolName}` : "tool_call";
  }
  return event.syscall;
}
