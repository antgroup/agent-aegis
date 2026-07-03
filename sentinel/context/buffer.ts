import type { ProbeEvent } from "../channel/event.js";

/**
 * SessionEventBuffer maintains a rolling window of enriched probe events
 * per session. It is the raw material that BehavioralSnapshot and
 * FeatureExtractor consume to build session-level context for AI / rule judges.
 *
 * The buffer receives events AFTER AttributionEngine enrichment, so every
 * BufferedEvent carries attribution, correlationId, and causalFlags.
 */

export interface SessionEventBufferOptions {
  /** Maximum events to retain per session (default 200). */
  maxPerSession?: number;
  /** Maximum number of sessions to track before evicting LRU (default 64). */
  maxSessions?: number;
  /** Time-based expiry for idle sessions in ms (default 300000 = 5 min). */
  sessionTtlMs?: number;
}

/**
 * A compact projection of ProbeEvent designed for AI consumption.
 * Omits the full `args` object (potentially large / binary) in favor of
 * a one-line `argsSummary`. Key scalars from `proc` / `net` are promoted
 * to top-level fields for compactness.
 */
export interface BufferedEvent {
  id: string;
  timestamp: number;
  source: string;
  syscall: string;
  pid: number;
  ppid: number;
  sessionKey: string;
  runId: string | undefined;
  toolName: string | undefined;
  comm: string | undefined;
  exe: string | undefined;
  correlationId: string | undefined;
  attribution: string | undefined;
  causalFlags: string[] | undefined;
  /** Summarized args: path for openat/execve, addr for connect, etc. */
  argsSummary: string | undefined;
  /** Network destination address (for connect events). */
  destAddr: string | undefined;
  /** Network destination port (for connect events). */
  destPort: number | undefined;
}

/** Extract a BufferedEvent from a ProbeEvent. */
function toBufferedEvent(event: ProbeEvent): BufferedEvent {
  let argsSummary: string | undefined;
  let destAddr: string | undefined;
  let destPort: number | undefined;

  // Build a compact args summary based on syscall type.
  const args = event.args ?? {};
  if (typeof args.path === "string") {
    argsSummary = args.path;
  } else if (Array.isArray(args.argv)) {
    argsSummary = args.argv.map(String).join(" ");
  }
  if (typeof args.addr === "string") {
    destAddr = args.addr;
    if (typeof args.port === "number") destPort = args.port;
  }
  // Also pick up net.* for connect events enriched by the ebpf runner.
  if (!destAddr && typeof event.net?.daddr === "string") {
    destAddr = event.net.daddr;
  }
  if (!destPort && typeof event.net?.dport === "number") {
    destPort = event.net.dport;
  }

  return {
    id: event.id,
    timestamp: event.timestamp,
    source: event.source,
    syscall: event.syscall,
    pid: event.pid,
    ppid: event.proc?.ppid ?? 0,
    sessionKey: event.sessionKey ?? "_default",
    runId: event.runId ?? undefined,
    toolName: event.toolName ?? undefined,
    comm: event.proc?.comm ?? undefined,
    exe: event.proc?.exe ?? undefined,
    correlationId: event.correlationId ?? undefined,
    attribution: (event.meta?.attribution as string) ?? undefined,
    causalFlags: (event.meta?.causalFlags as string[] | undefined) ?? undefined,
    argsSummary,
    destAddr,
    destPort,
  };
}

export class SessionEventBuffer {
  private readonly eventsBySession = new Map<string, BufferedEvent[]>();
  private readonly accessTimes = new Map<string, number>();
  private readonly maxPerSession: number;
  private readonly maxSessions: number;
  private readonly sessionTtlMs: number;

  constructor(opts: SessionEventBufferOptions = {}) {
    this.maxPerSession = opts.maxPerSession ?? 200;
    this.maxSessions = opts.maxSessions ?? 64;
    this.sessionTtlMs = opts.sessionTtlMs ?? 5 * 60 * 1000;
  }

  /**
   * Push an enriched ProbeEvent into the session buffer.
   * Deduplicates by event.id (if the same event is at the tail, skip).
   */
  push(event: ProbeEvent): void {
    const sessionKey = event.sessionKey ?? "_default";
    const now = Date.now();
    this.accessTimes.set(sessionKey, now);

    let events = this.eventsBySession.get(sessionKey);
    if (!events) {
      events = [];
      this.eventsBySession.set(sessionKey, events);
    }

    // Dedup: if the tail event has the same id, skip.
    if (events.length > 0 && events[events.length - 1].id === event.id) {
      return;
    }

    events.push(toBufferedEvent(event));

    // Enforce maxPerSession by dropping oldest.
    while (events.length > this.maxPerSession) {
      events.shift();
    }

    // Enforce maxSessions by evicting LRU.
    if (this.eventsBySession.size > this.maxSessions) {
      this.prune();
    }
  }

  /**
   * Get the buffered events for a session (oldest first).
   * Returns a defensive copy.
   */
  getEvents(sessionKey: string): BufferedEvent[] {
    const events = this.eventsBySession.get(sessionKey);
    return events ? [...events] : [];
  }

  /** Get the session keys currently tracked. */
  getSessionKeys(): string[] {
    return [...this.eventsBySession.keys()];
  }

  /**
   * Prune expired sessions and enforce maxSessions with LRU eviction.
   */
  prune(): void {
    const now = Date.now();

    // 1. Remove sessions past their TTL.
    const ttlExpired: string[] = [];
    for (const [key, lastAccess] of this.accessTimes) {
      if (now - lastAccess > this.sessionTtlMs) {
        ttlExpired.push(key);
      }
    }
    for (const key of ttlExpired) {
      this.eventsBySession.delete(key);
      this.accessTimes.delete(key);
    }

    // 2. If still over maxSessions, evict LRU.
    while (this.eventsBySession.size > this.maxSessions) {
      let oldestKey: string | undefined;
      let oldestTime = Infinity;
      for (const [key, lastAccess] of this.accessTimes) {
        if (lastAccess < oldestTime) {
          oldestTime = lastAccess;
          oldestKey = key;
        }
      }
      if (oldestKey !== undefined) {
        this.eventsBySession.delete(oldestKey);
        this.accessTimes.delete(oldestKey);
      } else {
        break;
      }
    }
  }

  /** Number of active sessions. */
  get sessionCount(): number {
    return this.eventsBySession.size;
  }

  /** Total events across all sessions. */
  get totalEvents(): number {
    let total = 0;
    for (const events of this.eventsBySession.values()) {
      total += events.length;
    }
    return total;
  }
}