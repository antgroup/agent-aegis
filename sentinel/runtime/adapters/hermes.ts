import type {
  AgentContext,
  AgentLogger,
  AgentRuntime,
  AgentRuntimeCapabilities,
  ToolCallAttempt,
  VerdictApplication,
} from "../types.js";

/**
 * Hermes → sentinel adapter (draft, M6).
 *
 * Unlike the OpenClaw adapter which subscribes to host hooks, the Hermes
 * adapter receives context updates through an explicit `pushContext` API
 * because the Node side of Hermes is the **RPC callee**, not a plugin with
 * hook subscriptions. Hermes's `rpc-handlers.ts` is expected to call
 * `pushContext` whenever the Python side sends fresh session/run info.
 *
 * The adapter is shipped in M6 alongside its tests; wiring it into the
 * actual RPC server (`rpc-server.ts` / `rpc-handlers.ts`) is intentionally
 * out of scope — that integration touches Python and the end-to-end Hermes
 * stack, which deserves a dedicated PR.
 */

export interface HermesRuntimeOptions {
  stateDir: string;
  config?: Record<string, unknown>;
  logger?: AgentLogger;
  initialContext?: Partial<AgentContext>;
  capabilities?: Partial<AgentRuntimeCapabilities>;
}

export interface HermesRuntimeHandle {
  readonly runtime: AgentRuntime;
  /**
   * Merge fields into the live AgentContext and fan out to subscribers.
   * Pass `pids` as a full replacement (not appended).
   */
  pushContext(update: Partial<AgentContext>): void;
  /** Fire all onShutdown callbacks. Idempotent. */
  signalShutdown(): Promise<void>;
}

const stderrLogger: AgentLogger = {
  debug: (m, ...a) => process.stderr.write(`[sentinel.hermes] DEBUG ${format(m, a)}\n`),
  info: (m, ...a) => process.stderr.write(`[sentinel.hermes] INFO  ${format(m, a)}\n`),
  warn: (m, ...a) => process.stderr.write(`[sentinel.hermes] WARN  ${format(m, a)}\n`),
  error: (m, ...a) => process.stderr.write(`[sentinel.hermes] ERROR ${format(m, a)}\n`),
};

function format(msg: string, args: unknown[]): string {
  if (args.length === 0) return msg;
  const parts = args.map((a) => {
    try {
      return typeof a === "string" ? a : JSON.stringify(a);
    } catch {
      return String(a);
    }
  });
  return `${msg} ${parts.join(" ")}`;
}

function detectPlatform(): AgentRuntimeCapabilities["platform"] {
  switch (process.platform) {
    case "linux":
      return "linux";
    case "darwin":
      return "darwin";
    case "win32":
      return "win32";
    default:
      return "unknown";
  }
}

export function createHermesRuntime(opts: HermesRuntimeOptions): HermesRuntimeHandle {
  const ctx: AgentContext = {
    sessionKey: opts.initialContext?.sessionKey ?? "default",
    runId: opts.initialContext?.runId,
    toolName: opts.initialContext?.toolName,
    pids: opts.initialContext?.pids ?? [process.pid],
    meta: opts.initialContext?.meta,
  };
  const logger = opts.logger ?? stderrLogger;
  const subscribers = new Set<(c: AgentContext) => void>();
  const shutdownCbs: Array<() => Promise<void>> = [];
  let shuttingDown = false;

  const capabilities: AgentRuntimeCapabilities = {
    canBlockToolCall: false,
    canTerminateProcess: false,
    platform: detectPlatform(),
    ...opts.capabilities,
  };

  const runtime: AgentRuntime = {
    name: "hermes",
    logger,
    capabilities,
    getCurrentContext: () => ({ ...ctx, pids: [...ctx.pids] }),
    onContextChange: (cb) => {
      subscribers.add(cb);
      return () => {
        subscribers.delete(cb);
      };
    },
    registerToolCallInterceptor: (_handler: (a: ToolCallAttempt) => Promise<VerdictApplication>) => {
      // Hermes does not deliver tool calls through this surface — Python's
      // tool_wrappers.py handles blocking via handler replacement. Store
      // nothing; future Hermes integration that wants sentinel-driven
      // tool-call decisions will need to push a synthetic attempt.
    },
    onShutdown: (cb) => {
      shutdownCbs.push(cb);
    },
    readConfig: async () => opts.config ?? {},
    getStateDir: () => opts.stateDir,
  };

  function pushContext(update: Partial<AgentContext>): void {
    if (update.sessionKey !== undefined) ctx.sessionKey = update.sessionKey;
    if ("runId" in update) ctx.runId = update.runId;
    if ("toolName" in update) ctx.toolName = update.toolName;
    if (update.pids !== undefined) ctx.pids = [...update.pids];
    if (update.meta !== undefined) ctx.meta = update.meta;
    for (const cb of subscribers) {
      try {
        cb(ctx);
      } catch (err) {
        logger.warn(`pushContext subscriber threw: ${String(err)}`);
      }
    }
  }

  async function signalShutdown(): Promise<void> {
    if (shuttingDown) return;
    shuttingDown = true;
    for (const cb of shutdownCbs) {
      try {
        await cb();
      } catch (err) {
        logger.warn(`onShutdown callback threw: ${String(err)}`);
      }
    }
  }

  return { runtime, pushContext, signalShutdown };
}
