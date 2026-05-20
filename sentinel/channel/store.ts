import fs from "node:fs";
import path from "node:path";
import type { AggregatedVerdict, ProbeEvent } from "./event.js";

const EVENTS_SUBDIR = "probe-events";

export interface ProbeEventStoreOptions {
  /** Base state directory provided by the agent runtime. Events go under `<stateDir>/probe-events/`. */
  stateDir: string;
  /**
   * Override for current date. Mainly a hook for tests; production uses `new Date()`.
   * Should return UTC date components.
   */
  now?: () => Date;
}

interface OpenHandle {
  date: string;
  stream: fs.WriteStream;
}

/**
 * Append-only JSONL store with daily rotation (UTC).
 *
 * One line per record. Records can be raw {@link ProbeEvent} or an
 * {@link AggregatedVerdict} envelope; both are stored in the same JSONL stream
 * with a discriminator `kind` field. Keeping both in one file preserves
 * causal ordering between event capture and verdict.
 */
export class ProbeEventStore {
  private readonly dir: string;
  private readonly now: () => Date;
  private handle: OpenHandle | null = null;
  private closed = false;

  constructor(opts: ProbeEventStoreOptions) {
    this.dir = path.join(opts.stateDir, EVENTS_SUBDIR);
    this.now = opts.now ?? (() => new Date());
    fs.mkdirSync(this.dir, { recursive: true });
  }

  appendEvent(event: ProbeEvent): void {
    this.write({ kind: "event", ...event });
  }

  appendVerdict(eventId: string, verdict: AggregatedVerdict): void {
    this.write({ kind: "verdict", eventId, ...verdict });
  }

  /** Current active file path (mainly for tests / diagnostics). */
  currentFile(): string {
    return path.join(this.dir, `events-${this.dateKey()}.jsonl`);
  }

  async close(): Promise<void> {
    this.closed = true;
    if (!this.handle) return;
    const stream = this.handle.stream;
    this.handle = null;
    await new Promise<void>((resolve) => stream.end(resolve));
  }

  private write(record: Record<string, unknown>): void {
    if (this.closed) return;
    const today = this.dateKey();
    if (!this.handle || this.handle.date !== today) {
      this.rotate(today);
    }
    this.handle!.stream.write(`${JSON.stringify(record)}\n`);
  }

  private rotate(date: string): void {
    if (this.handle) {
      this.handle.stream.end();
    }
    const file = path.join(this.dir, `events-${date}.jsonl`);
    const stream = fs.createWriteStream(file, { flags: "a" });
    this.handle = { date, stream };
  }

  private dateKey(): string {
    const d = this.now();
    const y = d.getUTCFullYear();
    const m = String(d.getUTCMonth() + 1).padStart(2, "0");
    const day = String(d.getUTCDate()).padStart(2, "0");
    return `${y}-${m}-${day}`;
  }
}
