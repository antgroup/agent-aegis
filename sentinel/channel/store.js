import fs from "node:fs";
import path from "node:path";
const EVENTS_SUBDIR = "probe-events";
/**
 * Append-only JSONL store with daily rotation (UTC).
 *
 * One line per record. Records can be raw {@link ProbeEvent} or an
 * {@link AggregatedVerdict} envelope; both are stored in the same JSONL stream
 * with a discriminator `kind` field. Keeping both in one file preserves
 * causal ordering between event capture and verdict.
 */
export class ProbeEventStore {
    dir;
    now;
    handle = null;
    closed = false;
    constructor(opts) {
        this.dir = path.join(opts.stateDir, EVENTS_SUBDIR);
        this.now = opts.now ?? (() => new Date());
        fs.mkdirSync(this.dir, { recursive: true });
    }
    appendEvent(event) {
        this.write({ kind: "event", ...event });
    }
    appendVerdict(eventId, verdict) {
        this.write({ kind: "verdict", eventId, ...verdict });
    }
    /** Current active file path (mainly for tests / diagnostics). */
    currentFile() {
        return path.join(this.dir, `events-${this.dateKey()}.jsonl`);
    }
    async close() {
        this.closed = true;
        if (!this.handle)
            return;
        const stream = this.handle.stream;
        this.handle = null;
        await new Promise((resolve) => stream.end(resolve));
    }
    write(record) {
        if (this.closed)
            return;
        const today = this.dateKey();
        if (!this.handle || this.handle.date !== today) {
            this.rotate(today);
        }
        this.handle.stream.write(`${JSON.stringify(record)}\n`);
    }
    rotate(date) {
        if (this.handle) {
            this.handle.stream.end();
        }
        const file = path.join(this.dir, `events-${date}.jsonl`);
        const stream = fs.createWriteStream(file, { flags: "a" });
        this.handle = { date, stream };
    }
    dateKey() {
        const d = this.now();
        const y = d.getUTCFullYear();
        const m = String(d.getUTCMonth() + 1).padStart(2, "0");
        const day = String(d.getUTCDate()).padStart(2, "0");
        return `${y}-${m}-${day}`;
    }
}
