/**
 * LSM policy snapshot.
 *
 * The aggregator emits verdicts faster than the kernel can be reconfigured,
 * so high-severity deny verdicts get translated into a policy entry kept in
 * this table, and the Go LSM runner replicates the table into a BPF
 * `policy_map`. Subsequent matching syscalls are denied in-kernel.
 *
 * Key insight: enforcement is **eventually-consistent**. The first occurrence
 * of an attack is observed-only (judges decide); the second occurrence is
 * denied at the LSM hook. This is the explicit trade-off chosen over
 * synchronous user-space blocking (which we previously did with Frida and
 * which had P99 ~200ms fail-open characteristics).
 */
import type { AggregatedVerdict } from "../../channel/event.js";
import type { VerdictSeverity } from "../../channel/schema.js";

export type PolicyKind = "exec_path" | "open_path" | "connect_addr";

export interface PolicyEntry {
  kind: PolicyKind;
  /** Path prefix or IPv4 in dotted form. Empty string = match-all (reserved). */
  value: string;
  /** Severity at insertion time; the runner uses it for logging only. */
  severity: VerdictSeverity;
  /** Epoch ms when this entry expires and the runner should evict it. */
  expiresAt: number;
  /** Verdict id for traceability — typically `final.judgeId`. */
  source: string;
}

export interface PolicyTableOptions {
  ttlMs: number;
  maxEntries: number;
  /** "high" or "critical". Verdicts below this severity are ignored. */
  minSeverity: VerdictSeverity;
  /** Test seam — defaults to Date.now. */
  now?: () => number;
}

export class PolicyTable {
  private entries: PolicyEntry[] = [];
  private opts: Required<Omit<PolicyTableOptions, "now">> & { now: () => number };

  constructor(opts: PolicyTableOptions) {
    this.opts = {
      ttlMs: opts.ttlMs,
      maxEntries: opts.maxEntries,
      minSeverity: opts.minSeverity,
      now: opts.now ?? Date.now,
    };
  }

  /**
   * Translate an AggregatedVerdict into one or zero policy entries.
   * Returns the inserted entry, or null when the verdict doesn't qualify.
   */
  ingest(v: AggregatedVerdict): PolicyEntry | null {
    if (v.final.action !== "block") return null;
    if (!severityAtLeast(v.final.severity, this.opts.minSeverity)) return null;

    const entry = translateVerdict(v, this.opts.ttlMs, this.opts.now());
    if (!entry) return null;

    this.pruneExpired();
    // Deduplicate: same (kind, value) refreshes TTL rather than appending.
    const idx = this.entries.findIndex(
      (e) => e.kind === entry.kind && e.value === entry.value,
    );
    if (idx >= 0) {
      this.entries[idx] = entry;
    } else {
      this.entries.push(entry);
    }
    // LRU: drop the oldest if we hit the cap.
    if (this.entries.length > this.opts.maxEntries) {
      this.entries.sort((a, b) => a.expiresAt - b.expiresAt);
      this.entries = this.entries.slice(-this.opts.maxEntries);
    }
    return entry;
  }

  list(): readonly PolicyEntry[] {
    this.pruneExpired();
    return this.entries;
  }

  clear(): void {
    this.entries = [];
  }

  size(): number {
    this.pruneExpired();
    return this.entries.length;
  }

  private pruneExpired(): void {
    const now = this.opts.now();
    this.entries = this.entries.filter((e) => e.expiresAt > now);
  }
}

const SEVERITY_RANK: Record<VerdictSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

function severityAtLeast(actual: VerdictSeverity, min: VerdictSeverity): boolean {
  return SEVERITY_RANK[actual] >= SEVERITY_RANK[min];
}

/**
 * Map a verdict to a single policy entry by inspecting the originating event.
 * We rely on the aggregator carrying enough info inside `final.reason` /
 * source verdicts; here we pull the deny key from the **first source verdict
 * that carries a sideEffect with the path** — but since side effects in the
 * current schema don't carry that information directly, we instead read the
 * reason field for path hints in the format `path=…` / `addr=…`. The native
 * judge already writes that into reason for sensitive-path and kernel-escape.
 *
 * If you change the native judge to use structured side effects, update this
 * function in lockstep.
 */
export function translateVerdict(
  v: AggregatedVerdict,
  ttlMs: number,
  now: number,
): PolicyEntry | null {
  const reason = v.final.reason || "";
  const judgeId = v.final.judgeId || "unknown";
  const expiresAt = now + ttlMs;

  // Sensitive path / kernel escape: judge reason ends with `path=<path>`.
  const pathMatch = reason.match(/path=([^\s;,]+)/);
  if (pathMatch) {
    const value = pathMatch[1];
    // execve-style judges report kernel-escape; openat-style report sensitive-path.
    const kind: PolicyKind = /kernel-escape|exec/i.test(judgeId)
      ? "exec_path"
      : "open_path";
    return { kind, value, severity: v.final.severity, expiresAt, source: judgeId };
  }

  // Connect: reason contains `addr=<ipv4>`.
  const addrMatch = reason.match(/addr=([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/);
  if (addrMatch) {
    return {
      kind: "connect_addr",
      value: addrMatch[1],
      severity: v.final.severity,
      expiresAt,
      source: judgeId,
    };
  }

  return null;
}

/**
 * Wire-format for the Go runner. Each entry on its own line keeps the socket
 * protocol trivially parseable on both ends.
 */
export interface PolicyMessage {
  kind: "policy_upsert" | "policy_clear";
  entry?: PolicyEntry;
}

export function encodePolicyMessage(msg: PolicyMessage): string {
  return JSON.stringify(msg) + "\n";
}
