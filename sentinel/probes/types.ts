import type { AggregatedVerdict, ProbeEvent } from "../channel/event.js";
import type { AgentRuntime } from "../runtime/types.js";

/**
 * Dependencies handed to a probe at start time.
 *
 * The probe should NOT capture references to anything else inside the
 * sentinel — sticking to these two surfaces keeps probes drop-in replaceable
 * (ebpf tracepoint, uprobe, LSM enforce, future probes).
 */
export interface ProbeDeps {
  readonly runtime: AgentRuntime;
  /**
   * Publish an event through the sentinel pipeline. Returns the aggregated
   * verdict (or null when no judges are registered / all abstained).
   *
   * Observe-mode probes may ignore the returned value.
   */
  publish: (event: ProbeEvent) => Promise<AggregatedVerdict | null>;
  /**
   * Subscribe to every aggregated verdict the sentinel emits — regardless of
   * which probe sourced the original event. Returns an unsubscribe function.
   *
   * Used by enforce-side probes (M7.5 LSM): translate high-severity deny
   * verdicts into kernel policy entries so subsequent matching syscalls are
   * blocked in-kernel.
   */
  onVerdict: (cb: (verdict: AggregatedVerdict) => void) => () => void;
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
