/**
 * Wire protocol for the uprobe runner. One JSON object per stdout line.
 * Schema mirrors the eBPF runner's messages.ts so the loader-side logic stays
 * symmetric; the only material difference is that `source` is set to "uprobe"
 * downstream.
 */
export type UprobeMessage = UprobeReady | UprobeSyscall | UprobeLog;

export interface UprobeReady {
  kind: "ready";
  probes: string[];
}

export interface UprobeSyscall {
  kind: "syscall";
  syscall: string;
  pid: number;
  ppid?: number;
  ts: number;
  argv?: string[];
  path?: string;
  addr?: string;
  comm?: string;
  /** SSL_write / SSL_read payload preview (truncated by the runner). */
  preview?: string;
  extra?: Record<string, unknown>;
}

export interface UprobeLog {
  kind: "log";
  level: "debug" | "info" | "warn" | "error";
  message: string;
}

export function parseUprobeMessage(line: string): UprobeMessage | null {
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
    case "syscall":
      return parseSyscall(r);
    case "log":
      return parseLog(r);
    default:
      return null;
  }
}

function parseReady(r: Record<string, unknown>): UprobeReady | null {
  if (!Array.isArray(r.probes)) return null;
  if (!r.probes.every((p) => typeof p === "string")) return null;
  return { kind: "ready", probes: r.probes as string[] };
}

function parseSyscall(r: Record<string, unknown>): UprobeSyscall | null {
  if (typeof r.syscall !== "string") return null;
  const pid = typeof r.pid === "number" ? r.pid : 0;
  const ts = typeof r.ts === "number" ? r.ts : Date.now();
  const out: UprobeSyscall = { kind: "syscall", syscall: r.syscall, pid, ts };
  if (typeof r.ppid === "number") out.ppid = r.ppid;
  if (Array.isArray(r.argv) && r.argv.every((s) => typeof s === "string")) {
    out.argv = r.argv as string[];
  }
  if (typeof r.path === "string") out.path = r.path;
  if (typeof r.addr === "string") out.addr = r.addr;
  if (typeof r.comm === "string") out.comm = r.comm;
  if (typeof r.preview === "string") out.preview = r.preview;
  if (r.extra && typeof r.extra === "object" && !Array.isArray(r.extra)) {
    out.extra = r.extra as Record<string, unknown>;
  }
  return out;
}

function parseLog(r: Record<string, unknown>): UprobeLog | null {
  const level = r.level;
  if (level !== "debug" && level !== "info" && level !== "warn" && level !== "error") return null;
  if (typeof r.message !== "string") return null;
  return { kind: "log", level, message: r.message };
}
