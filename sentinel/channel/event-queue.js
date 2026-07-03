export class EventQueue {
    queue = [];
    maxDepth;
    sampleRate;
    onDrop;
    handler;
    _dropped = 0;
    _sampled = 0;
    _enqueued = 0;
    _processed = 0;
    processing = false;
    pendingHandlers = new Set();
    constructor(handler, opts = {}) {
        this.handler = handler;
        this.maxDepth = opts.maxDepth ?? 4096;
        this.sampleRate = opts.sampleRate ?? 1.0;
        this.onDrop = opts.onDrop;
    }
    /**
     * Enqueue an event. Returns true if the event was accepted (queued or
     * directly processed), false if it was dropped.
     *
     * Dropping can happen for two reasons:
     * 1. **sampled** — the sampleRate pre-emptively rejects the event.
     * 2. **queue_full** — the queue is at capacity.
     *
     * In both cases `onDrop` is called and the respective counter increments.
     */
    enqueue(event) {
        // Pre-emptive sampling. Use a simple mixing function over the event id
        // for better distribution than pid/timestamp XOR (which clusters when
        // timestamps are close together, as they are in burst events).
        if (this.sampleRate < 1.0) {
            // FNV-1a-like hash of the event id string for uniform distribution.
            let h = 2166136261;
            for (let i = 0; i < event.id.length; i++) {
                h ^= event.id.charCodeAt(i);
                h = (h * 16777619) >>> 0;
            }
            if ((h & 0xffff) / 0xffff >= this.sampleRate) {
                this._sampled++;
                this.onDrop?.(1, "sampled");
                return false;
            }
        }
        // Queue-full drop.
        if (this.queue.length >= this.maxDepth) {
            this._dropped++;
            this.onDrop?.(1, "queue_full");
            return false;
        }
        this.queue.push(event);
        this._enqueued++;
        this.scheduleFlush();
        return true;
    }
    /** Current depth of the pending queue. */
    get size() {
        return this.queue.length;
    }
    /** Total events dropped because the queue was full. */
    get dropped() {
        return this._dropped;
    }
    /** Total events discarded by sampling. */
    get sampled() {
        return this._sampled;
    }
    /** Total events successfully enqueued (not counting sampled/dropped). */
    get enqueued() {
        return this._enqueued;
    }
    /** Total events processed (handler called). */
    get processed() {
        return this._processed;
    }
    /**
     * Reset the drop/sample counters (e.g. after writing a drop-marker so
     * the next marker only covers the delta).
     */
    resetCounters() {
        const d = this._dropped;
        const s = this._sampled;
        this._dropped = 0;
        this._sampled = 0;
        return { dropped: d, sampled: s };
    }
    /** Flush all pending events and wait for async handlers (for tests / shutdown). */
    async flush() {
        while (this.queue.length > 0) {
            this.processOne(this.queue.shift());
        }
        await this.waitForHandlers();
    }
    scheduleFlush() {
        if (this.processing)
            return;
        this.processing = true;
        // Use setImmediate (or Promise.resolve as fallback) to drain the queue
        // on the next event-loop tick. This ensures that a burst of enqueue()
        // calls batches into a single flush cycle.
        const scheduleNext = typeof globalThis.setImmediate === "function"
            ? globalThis.setImmediate
            : (cb) => Promise.resolve().then(cb);
        scheduleNext(() => {
            this.drain();
        });
    }
    drain() {
        // Drain up to 256 events per tick to avoid starving the event loop under
        // very high throughput. Remaining events are rescheduled.
        const batch = Math.min(this.queue.length, 256);
        for (let i = 0; i < batch; i++) {
            this.processOne(this.queue.shift());
        }
        if (this.queue.length > 0) {
            this.scheduleFlush();
        }
        else {
            this.processing = false;
        }
    }
    processOne(event) {
        this._processed++;
        try {
            const pending = Promise.resolve(this.handler(event))
                .catch(() => {
                // Swallow — the bus layer handles error reporting per subscriber.
            })
                .finally(() => {
                this.pendingHandlers.delete(pending);
            });
            this.pendingHandlers.add(pending);
        }
        catch {
            // Swallow — the bus layer handles error reporting per subscriber.
        }
    }
    async waitForHandlers() {
        while (this.pendingHandlers.size > 0) {
            await Promise.all([...this.pendingHandlers]);
        }
    }
}
