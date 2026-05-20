import type { AggregatedVerdict, ProbeEvent } from "../channel/event.js";
import type { AgentRuntime } from "../runtime/types.js";

/**
 * Dependencies handed to a probe at start time.
 *
 * The probe should NOT capture references to anything else inside the
 * sentinel — sticking to these two surfaces keeps probes drop-in replaceable
 * (M4 Frida, M5 eBPF, future userspace tracers).
 */
export interface ProbeDeps {
  readonly runtime: AgentRuntime;
  /**
   * Publish an event through the sentinel pipeline. Returns the aggregated
   * verdict (or null when no judges are registered / all abstained).
   *
   * Observe-mode probes may ignore the returned value; M4.5 enforce-mode
   * relies on it for the agent-side deny path.
   */
  publish: (event: ProbeEvent) => Promise<AggregatedVerdict | null>;
}

/**
 * A probe produces ProbeEvents from outside the sentinel core (syscall
 * tracers, network sniffers, IPC interceptors, …) and feeds them into the
 * judge pipeline via `deps.publish`.
 *
 * Lifecycle:
 *   - `start(deps)` is called when the probe is registered; it should set up
 *     all attachments and return only after the probe is producing events or
 *     has positively determined it cannot run (in which case it should log
 *     and return silently).
 *   - `stop()` must be idempotent; sentinel calls it during `SentinelHandle.stop()`.
 */
export interface Probe {
  readonly id: string;
  start(deps: ProbeDeps): Promise<void>;
  stop(): Promise<void>;
}
