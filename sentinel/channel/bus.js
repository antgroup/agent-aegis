/**
 * Tiny in-process pub-sub.
 *
 * Handlers run via Promise.resolve().then so that a slow or throwing
 * subscriber cannot block the publisher; errors are swallowed and reported
 * via the optional onError callback (the sentinel wires it to the runtime
 * logger). Order of delivery between handlers is not guaranteed.
 */
export class ProbeEventBus {
    handlers = new Set();
    onError;
    constructor(opts = {}) {
        this.onError = opts.onError ?? (() => { });
    }
    subscribe(handler) {
        this.handlers.add(handler);
        return () => {
            this.handlers.delete(handler);
        };
    }
    publish(event) {
        for (const handler of this.handlers) {
            Promise.resolve()
                .then(() => handler(event))
                .catch((err) => this.onError(err, event));
        }
    }
    size() {
        return this.handlers.size;
    }
    clear() {
        this.handlers.clear();
    }
}
