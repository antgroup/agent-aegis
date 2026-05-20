/**
 * Wire protocol between the Python BCC runner and the Node loader.
 *
 * One JSON object per stdout line. Adding new `kind` values is forward
 * compatible — the loader drops unknown kinds.
 */
export type EbpfMessage = EbpfReady | EbpfSyscall | EbpfLog;

export interface EbpfReady {
  kind: "ready";
  probes: string[];
}

export interface EbpfSyscall {
  kind: "syscall";
  syscall: string;
  pid: number;
  /** Parent PID — eBPF tracepoints can read this; populated when available. */
  ppid?: number;
  /** Probe wall-clock timestamp in milliseconds. */
  ts: number;
  argv?: string[];
  path?: string;
  addr?: string;
  comm?: string;
  extra?: Record<string, unknown>;
}

export interface EbpfLog {
  kind: "log";
  level: "debug" | "info" | "warn" | "error";
  message: string;
}

/**
 * Parse one JSONL line emitted by the BCC runner. Returns null for empty
 * lines, syntax errors, or unknown `kind` values. Designed to be loud
 * (caller logs) about garbage rather than failing hard.
 */
export function parseEbpfMessage(line: string): EbpfMessage | null {
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

function parseReady(r: Record<string, unknown>): EbpfReady | null {
  if (!Array.isArray(r.probes)) return null;
  if (!r.probes.every((p) => typeof p === "string")) return null;
  return { kind: "ready", probes: r.probes as string[] };
}

function parseSyscall(r: Record<string, unknown>): EbpfSyscall | null {
  if (typeof r.syscall !== "string") return null;
  const pid = typeof r.pid === "number" ? r.pid : 0;
  const ts = typeof r.ts === "number" ? r.ts : Date.now();
  const out: EbpfSyscall = { kind: "syscall", syscall: r.syscall, pid, ts };
  if (typeof r.ppid === "number") out.ppid = r.ppid;
  if (Array.isArray(r.argv) && r.argv.every((s) => typeof s === "string")) {
    out.argv = r.argv as string[];
  }
  if (typeof r.path === "string") out.path = r.path;
  if (typeof r.addr === "string") out.addr = r.addr;
  if (typeof r.comm === "string") out.comm = r.comm;
  if (r.extra && typeof r.extra === "object" && !Array.isArray(r.extra)) {
    out.extra = r.extra as Record<string, unknown>;
  }
  return out;
}

function parseLog(r: Record<string, unknown>): EbpfLog | null {
  const level = r.level;
  if (level !== "debug" && level !== "info" && level !== "warn" && level !== "error") return null;
  if (typeof r.message !== "string") return null;
  return { kind: "log", level, message: r.message };
}
