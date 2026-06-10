/**
 * Wire protocol between the Python BCC runner and the Node loader.
 *
 * One JSON object per stdout line. Adding new `kind` values is forward
 * compatible — the loader drops unknown kinds. Adding new fields is also
 * forward compatible — parsers narrow defensively and ignore the rest.
 */
import type { ContainerInfo, NetInfo, ProcessInfo } from "../../channel/event.js";

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
  /** v2/M10 enrichment — process identity + lineage (best-effort, from /proc). */
  proc?: ProcessInfo;
  /** v2/M10 enrichment — container / namespace context. */
  container?: ContainerInfo;
  /** v2/M10 enrichment — structured connection info for network syscalls. */
  net?: NetInfo;
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
  const proc = narrowProc(r.proc);
  if (proc) out.proc = proc;
  const container = narrowContainer(r.container);
  if (container) out.container = container;
  const net = narrowNet(r.net);
  if (net) out.net = net;
  if (r.extra && typeof r.extra === "object" && !Array.isArray(r.extra)) {
    out.extra = r.extra as Record<string, unknown>;
  }
  return out;
}

// --- defensive field narrowers for the v2 enrichment objects -----------------

function asNum(v: unknown): number | undefined {
  return typeof v === "number" && Number.isFinite(v) ? v : undefined;
}
function asStr(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}
function asStrArr(v: unknown): string[] | undefined {
  return Array.isArray(v) && v.every((x) => typeof x === "string") ? (v as string[]) : undefined;
}
function asNumArr(v: unknown): number[] | undefined {
  return Array.isArray(v) && v.every((x) => typeof x === "number") ? (v as number[]) : undefined;
}
function asObj(v: unknown): Record<string, unknown> | undefined {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : undefined;
}
function compact<T extends object>(o: T): T | undefined {
  return Object.keys(o).length > 0 ? o : undefined;
}

export function narrowProc(v: unknown): ProcessInfo | undefined {
  const o = asObj(v);
  if (!o) return undefined;
  const p: ProcessInfo = {};
  if (asNum(o.tid) !== undefined) p.tid = asNum(o.tid);
  if (asNum(o.ppid) !== undefined) p.ppid = asNum(o.ppid);
  if (asNum(o.pgid) !== undefined) p.pgid = asNum(o.pgid);
  if (asNum(o.sid) !== undefined) p.sid = asNum(o.sid);
  if (asNum(o.uid) !== undefined) p.uid = asNum(o.uid);
  if (asNum(o.gid) !== undefined) p.gid = asNum(o.gid);
  if (asStr(o.comm) !== undefined) p.comm = asStr(o.comm);
  if (asStr(o.exe) !== undefined) p.exe = asStr(o.exe);
  if (asStr(o.cwd) !== undefined) p.cwd = asStr(o.cwd);
  if (asStrArr(o.cmdline) !== undefined) p.cmdline = asStrArr(o.cmdline);
  if (asNum(o.startTime) !== undefined) p.startTime = asNum(o.startTime);
  if (asNumArr(o.ancestors) !== undefined) p.ancestors = asNumArr(o.ancestors);
  return compact(p);
}

export function narrowContainer(v: unknown): ContainerInfo | undefined {
  const o = asObj(v);
  if (!o) return undefined;
  const c: ContainerInfo = {};
  if (asStr(o.cgroup) !== undefined) c.cgroup = asStr(o.cgroup);
  if (asNum(o.cgroupId) !== undefined) c.cgroupId = asNum(o.cgroupId);
  if (asNum(o.pidNs) !== undefined) c.pidNs = asNum(o.pidNs);
  if (asNum(o.netNs) !== undefined) c.netNs = asNum(o.netNs);
  if (asNum(o.mntNs) !== undefined) c.mntNs = asNum(o.mntNs);
  return compact(c);
}

export function narrowNet(v: unknown): NetInfo | undefined {
  const o = asObj(v);
  if (!o) return undefined;
  const n: NetInfo = {};
  if (asStr(o.family) !== undefined) n.family = asStr(o.family);
  if (asStr(o.proto) !== undefined) n.proto = asStr(o.proto);
  if (asStr(o.daddr) !== undefined) n.daddr = asStr(o.daddr);
  if (asNum(o.dport) !== undefined) n.dport = asNum(o.dport);
  if (asStr(o.saddr) !== undefined) n.saddr = asStr(o.saddr);
  if (asNum(o.sport) !== undefined) n.sport = asNum(o.sport);
  return compact(n);
}

function parseLog(r: Record<string, unknown>): EbpfLog | null {
  const level = r.level;
  if (level !== "debug" && level !== "info" && level !== "warn" && level !== "error") return null;
  if (typeof r.message !== "string") return null;
  return { kind: "log", level, message: r.message };
}
