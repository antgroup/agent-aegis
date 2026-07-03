import type { ProbeEvent } from "../channel/event.js";
import {
  SENSITIVE_PATTERNS as EXFIL_SENSITIVE_PATTERNS,
  WRITABLE_DIR_PATTERNS,
  isExternalAddr,
} from "../context/patterns.js";

/**
 * CausalChainDetector watches a sliding window of events per session and
 * detects cross-event attack patterns.
 *
 * M11 initial rules:
 * - **exfil**: same process tree does openat(sensitive path) then connect(external)
 * - **write-then-run**: same process tree does openat(writable path like /tmp)
 *   then execve(path under that writable dir)
 *
 * These are lightweight synchronous checks — no ML, no persistence.
 * M12 can extend with more sophisticated detection.
 */

export interface CausalChainOptions {
  /** How far back to look for preceding events (default 60s). */
  windowMs?: number;
  /** Max events to keep per session (default 500). */
  maxPerSession?: number;
}

/** A recent event kept in the sliding window. */
interface WindowedEvent {
  pid: number;
  ppid: number;
  syscall: string;
  path?: string;
  addr?: string;
  source: string;
  attribution?: string;
  ts: number;
}

export class CausalChainDetector {
  private readonly recentBySession = new Map<string, WindowedEvent[]>();
  private readonly windowMs: number;
  private readonly maxPerSession: number;

  constructor(opts: CausalChainOptions = {}) {
    this.windowMs = opts.windowMs ?? 60_000;
    this.maxPerSession = opts.maxPerSession ?? 500;
  }

  /**
   * Feed an event and check for causal patterns.
   * Returns an array of detected causal flags (may be empty).
   */
  check(event: ProbeEvent): string[] {
    const flags: string[] = [];
    const sessionKey = event.sessionKey ?? "_default";
    const now = event.timestamp;

    // Extract relevant fields.
    const we: WindowedEvent = {
      pid: event.pid,
      ppid: event.proc?.ppid ?? 0,
      syscall: event.syscall,
      path: (event.args?.path as string) ?? undefined,
      addr: (event.args?.addr as string) ?? undefined,
      source: event.source,
      attribution: event.meta?.attribution as string | undefined,
      ts: now,
    };

    const recent = this.getOrCreateWindow(sessionKey);

    // Check patterns against existing events.
    // Only check for agent/descendant events (external events are noise).
    if (we.attribution !== "external") {
      this.checkExfil(we, recent, flags);
      this.checkWriteThenRun(we, recent, flags);
    }

    // Add to window.
    recent.push(we);

    // Prune old entries.
    this.pruneWindow(recent, now);

    return flags;
  }

  /**
   * Exfil: same process tree read a sensitive file, then connected externally.
   * Pattern: openat(sensitive_path) ... connect(external_addr) within window.
   */
  private checkExfil(current: WindowedEvent, recent: WindowedEvent[], flags: string[]): void {
    if (current.syscall !== "connect" || !current.addr) return;

    const isExternal = isExternalAddr(current.addr);
    if (!isExternal) return;

    // Look back for a sensitive-path read within the window.
    for (const prev of recent) {
      if (current.ts - prev.ts > this.windowMs) continue;
      if (!this.sameProcessTree(current, prev)) continue;
      if (prev.syscall === "openat" && prev.path && this.isSensitivePath(prev.path)) {
        flags.push("exfil");
        return; // Only flag once per event.
      }
    }
  }

  /**
   * Write-then-run: same process tree wrote to a writable dir, then
   * executed a binary from that dir.
   * Pattern: openat(/tmp/...) ... execve(/tmp/...) within window.
   */
  private checkWriteThenRun(current: WindowedEvent, recent: WindowedEvent[], flags: string[]): void {
    if (current.syscall !== "execve" || !current.path) return;

    // Check if the executed path is under a writable directory.
    const isWritableDirExec = WRITABLE_DIR_PATTERNS.some((p) => p.test(current.path!));
    if (!isWritableDirExec) return;

    // Look back for a write/open to a path that matches the executed binary's directory.
    for (const prev of recent) {
      if (current.ts - prev.ts > this.windowMs) continue;
      if (!this.sameProcessTree(current, prev)) continue;
      if (prev.syscall === "openat" && prev.path && this.isWritableDirPath(prev.path)) {
        // Check if the openat path is a prefix of the execve path's directory.
        const execDir = current.path!.substring(0, current.path!.lastIndexOf("/") + 1);
        if (prev.path.startsWith(execDir) || execDir.startsWith(prev.path)) {
          flags.push("write_then_run");
          return;
        }
      }
    }
  }

  /** Check if two events are from the same process tree (same or parent/child). */
  private sameProcessTree(a: WindowedEvent, b: WindowedEvent): boolean {
    if (a.pid === b.pid) return true;
    if (a.ppid === b.pid || b.ppid === a.pid) return true;
    // Check grandparent.
    if (a.ppid > 0 && a.ppid === b.ppid) return true;
    if (b.ppid > 0 && b.ppid === a.ppid) return true;
    return false;
  }

  /** Check if a path matches sensitive file patterns. */
  private isSensitivePath(path: string): boolean {
    return EXFIL_SENSITIVE_PATTERNS.some((p) => p.test(path));
  }

  /** Check if a path is under a writable directory. */
  private isWritableDirPath(path: string): boolean {
    return WRITABLE_DIR_PATTERNS.some((p) => p.test(path));
  }

  private getOrCreateWindow(sessionKey: string): WindowedEvent[] {
    let recent = this.recentBySession.get(sessionKey);
    if (!recent) {
      recent = [];
      this.recentBySession.set(sessionKey, recent);
    }
    return recent;
  }

  private pruneWindow(recent: WindowedEvent[], now: number): void {
    const cutoff = now - this.windowMs;
    while (recent.length > 0 && recent[0].ts < cutoff) {
      recent.shift();
    }
    // Also cap by max entries.
    while (recent.length > this.maxPerSession) {
      recent.shift();
    }
  }

  /** Prune all expired windows across all sessions. */
  prune(): void {
    const now = Date.now();
    for (const [, recent] of this.recentBySession) {
      this.pruneWindow(recent, now);
    }
    // Remove empty sessions.
    for (const [key, recent] of this.recentBySession) {
      if (recent.length === 0) {
        this.recentBySession.delete(key);
      }
    }
  }

  /** Number of active sessions being tracked. */
  get sessionCount(): number {
    return this.recentBySession.size;
  }
}