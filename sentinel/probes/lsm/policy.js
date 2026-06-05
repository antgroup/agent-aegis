export class PolicyTable {
    entries = [];
    opts;
    constructor(opts) {
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
    ingest(v) {
        if (v.final.action !== "block")
            return null;
        if (!severityAtLeast(v.final.severity, this.opts.minSeverity))
            return null;
        const entry = translateVerdict(v, this.opts.ttlMs, this.opts.now());
        if (!entry)
            return null;
        this.pruneExpired();
        // Deduplicate: same (kind, value) refreshes TTL rather than appending.
        const idx = this.entries.findIndex((e) => e.kind === entry.kind && e.value === entry.value);
        if (idx >= 0) {
            this.entries[idx] = entry;
        }
        else {
            this.entries.push(entry);
        }
        // LRU: drop the oldest if we hit the cap.
        if (this.entries.length > this.opts.maxEntries) {
            this.entries.sort((a, b) => a.expiresAt - b.expiresAt);
            this.entries = this.entries.slice(-this.opts.maxEntries);
        }
        return entry;
    }
    list() {
        this.pruneExpired();
        return this.entries;
    }
    clear() {
        this.entries = [];
    }
    size() {
        this.pruneExpired();
        return this.entries.length;
    }
    pruneExpired() {
        const now = this.opts.now();
        this.entries = this.entries.filter((e) => e.expiresAt > now);
    }
}
const SEVERITY_RANK = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
};
function severityAtLeast(actual, min) {
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
export function translateVerdict(v, ttlMs, now) {
    const reason = v.final.reason || "";
    const judgeId = v.final.judgeId || "unknown";
    const expiresAt = now + ttlMs;
    // Sensitive path / kernel escape: judge reason ends with `path=<path>`.
    const pathMatch = reason.match(/path=([^\s;,]+)/);
    if (pathMatch) {
        const value = pathMatch[1];
        // execve-style judges report kernel-escape; openat-style report sensitive-path.
        const kind = /kernel-escape|exec/i.test(judgeId)
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
export function encodePolicyMessage(msg) {
    return JSON.stringify(msg) + "\n";
}
