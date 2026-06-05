/**
 * Wire protocol between the Go LSM runner and the Node loader.
 *
 * Direction:
 *  - Node → runner: PolicyMessage (policy_upsert / policy_clear) — see policy.ts
 *  - runner → Node: LsmRunnerMessage (this file) — ready / deny / log
 *
 * Both directions use JSON-per-line. The runner's deny events are surfaced
 * back through the sentinel pipeline as ProbeEvents with source="lsm" so
 * audit logs reflect what the kernel actually blocked.
 */
export type LsmRunnerMessage = LsmReady | LsmDeny | LsmLog;

export interface LsmReady {
  kind: "ready";
  /** Which LSM hooks attached (e.g. ["file_open", "bprm_check_security"]). */
  hooks: string[];
}

export interface LsmDeny {
  kind: "deny";
  /** Which LSM hook fired. */
  hook: string;
  /** PID of the denied process. */
  pid: number;
  ppid?: number;
  comm?: string;
  /** Path / addr that matched policy. */
  match: string;
  /** Epoch ms. */
  ts: number;
}

export interface LsmLog {
  kind: "log";
  level: "debug" | "info" | "warn" | "error";
  message: string;
}

export function parseLsmRunnerMessage(line: string): LsmRunnerMessage | null {
  const trimmed = line.trim();
  if (!trimmed) return null;
  let raw: unknown;
  try {
    raw = JSON.parse(trimmed);
  } catch {
    return null;
  }
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  switch (r.kind) {
    case "ready":
      return parseReady(r);
    case "deny":
      return parseDeny(r);
    case "log":
      return parseLog(r);
    default:
      return null;
  }
}

function parseReady(r: Record<string, unknown>): LsmReady | null {
  if (!Array.isArray(r.hooks)) return null;
  if (!r.hooks.every((s) => typeof s === "string")) return null;
  return { kind: "ready", hooks: r.hooks as string[] };
}

function parseDeny(r: Record<string, unknown>): LsmDeny | null {
  if (typeof r.hook !== "string") return null;
  if (typeof r.match !== "string") return null;
  const pid = typeof r.pid === "number" ? r.pid : 0;
  const ts = typeof r.ts === "number" ? r.ts : Date.now();
  const out: LsmDeny = { kind: "deny", hook: r.hook, match: r.match, pid, ts };
  if (typeof r.ppid === "number") out.ppid = r.ppid;
  if (typeof r.comm === "string") out.comm = r.comm;
  return out;
}

function parseLog(r: Record<string, unknown>): LsmLog | null {
  const level = r.level;
  if (level !== "debug" && level !== "info" && level !== "warn" && level !== "error") return null;
  if (typeof r.message !== "string") return null;
  return { kind: "log", level, message: r.message };
}
