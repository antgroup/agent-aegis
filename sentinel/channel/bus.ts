import type { ProbeEvent } from "./event.js";

export type ProbeEventHandler = (event: ProbeEvent) => void | Promise<void>;

/**
 * Tiny in-process pub-sub.
 *
 * Handlers run via Promise.resolve().then so that a slow or throwing
 * subscriber cannot block the publisher; errors are swallowed and reported
 * via the optional onError callback (the sentinel wires it to the runtime
 * logger). Order of delivery between handlers is not guaranteed.
 */
export class ProbeEventBus {
  private readonly handlers = new Set<ProbeEventHandler>();
  private readonly onError: (err: unknown, event: ProbeEvent) => void;

  constructor(opts: { onError?: (err: unknown, event: ProbeEvent) => void } = {}) {
    this.onError = opts.onError ?? (() => {});
  }

  subscribe(handler: ProbeEventHandler): () => void {
    this.handlers.add(handler);
    return () => {
      this.handlers.delete(handler);
    };
  }

  publish(event: ProbeEvent): void {
    for (const handler of this.handlers) {
      Promise.resolve()
        .then(() => handler(event))
        .catch((err) => this.onError(err, event));
    }
  }

  size(): number {
    return this.handlers.size;
  }

  clear(): void {
    this.handlers.clear();
  }
}
