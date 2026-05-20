import type { AggregatedVerdict, ProbeEvent } from "../channel/event.js";

/**
 * Framework-agnostic contract between sentinel and the agent it lives inside.
 *
 * sentinel core (channel/judges/index.ts) depends ONLY on this module. Any
 * agent framework (OpenClaw, Hermes, …) is plugged in by writing an adapter
 * under `sentinel/runtime/adapters/<framework>.ts` that returns an
 * AgentRuntime — sentinel core never imports from those adapters.
 */

export interface AgentLogger {
  debug(msg: string, ...args: unknown[]): void;
  info(msg: string, ...args: unknown[]): void;
  warn(msg: string, ...args: unknown[]): void;
  error(msg: string, ...args: unknown[]): void;
}

export type AgentPlatform = "linux" | "darwin" | "win32" | "unknown";

export interface AgentRuntimeCapabilities {
  /** Can the runtime synchronously block a tool call (true for OpenClaw before_tool_call). */
  canBlockToolCall: boolean;
  /** Is the runtime allowed to kill a child process by PID. */
  canTerminateProcess: boolean;
  /** OS family — sentinel uses this to decide which probes can run (e.g. eBPF only on linux). */
  platform: AgentPlatform;
}

export interface AgentContext {
  /** Session-level identifier. */
  sessionKey: string;
  /** Run / turn / tool-call lifecycle identifier. */
  runId?: string;
  /** Tool name if context is inside a tool call. */
  toolName?: string;
  /**
   * Set of PIDs that belong to the agent and should be observed by probes.
   * Maintained by the runtime adapter; sentinel does not discover PIDs itself.
   */
  pids: number[];
  /** Adapter-specific payload; sentinel does not inspect, only forwards into events. */
  meta?: Record<string, unknown>;
}

export interface ToolCallAttempt {
  toolName: string;
  params: unknown;
  ctx: AgentContext;
}

export interface VerdictApplication {
  /** Should the runtime block the underlying operation? */
  block: boolean;
  /** Reason surfaced back to the agent / user. */
  reason?: string;
  /** Aggregated verdict for audit / WebUI. */
  aggregated: AggregatedVerdict;
}

export interface AgentRuntime {
  readonly name: string;
  readonly logger: AgentLogger;
  readonly capabilities: AgentRuntimeCapabilities;

  /** Pulled once at sentinel start; later updates flow via onContextChange. */
  getCurrentContext(): AgentContext;

  /** Subscribe to context changes (session/run/tool/PID set updates). Returns unsubscribe. */
  onContextChange(cb: (ctx: AgentContext) => void): () => void;

  /**
   * Sentinel registers a single interceptor here; the runtime is responsible
   * for invoking it for each tool-call attempt and applying the resulting
   * VerdictApplication via whatever mechanism the framework supports.
   */
  registerToolCallInterceptor(
    handler: (attempt: ToolCallAttempt) => Promise<VerdictApplication>,
  ): void;

  /** Runtime fires this when the host process is shutting down. */
  onShutdown(cb: () => Promise<void>): void;

  /** Read configuration for sentinel and its judges. Shape is judge-defined. */
  readConfig(): Promise<Record<string, unknown>>;

  /** Where sentinel should persist event logs and any judge-local state. */
  getStateDir(): string;

  /**
   * Optional hook called every time the sentinel finishes processing an event
   * (after aggregation, before audit log). Adapters may forward to framework
   * event buses; sentinel does not require this to be implemented.
   */
  onSentinelEvent?(event: ProbeEvent, verdict: AggregatedVerdict | null): void;
}
