import os from "node:os";
import path from "node:path";
import type {
  AgentContext,
  AgentLogger,
  AgentRuntime,
  AgentRuntimeCapabilities,
  ToolCallAttempt,
  VerdictApplication,
} from "./types.js";

export interface NoopRuntimeOptions {
  name?: string;
  logger?: AgentLogger;
  stateDir?: string;
  capabilities?: Partial<AgentRuntimeCapabilities>;
  initialContext?: Partial<AgentContext>;
  config?: Record<string, unknown>;
}

const consoleLogger: AgentLogger = {
  debug: (m, ...a) => console.debug(`[sentinel] ${m}`, ...a),
  info: (m, ...a) => console.info(`[sentinel] ${m}`, ...a),
  warn: (m, ...a) => console.warn(`[sentinel] ${m}`, ...a),
  error: (m, ...a) => console.error(`[sentinel] ${m}`, ...a),
};

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

/**
 * Default in-process AgentRuntime used when sentinel runs without a real
 * agent framework attached — e.g. during unit tests or M1 smoke startup.
 *
 * It never intercepts tool calls, never reports PIDs, and silently swallows
 * shutdown callbacks (the test runner / OpenClaw plugin lifecycle handles
 * teardown).
 */
export function createNoopRuntime(opts: NoopRuntimeOptions = {}): AgentRuntime {
  const ctx: AgentContext = {
    sessionKey: opts.initialContext?.sessionKey ?? "noop",
    runId: opts.initialContext?.runId,
    toolName: opts.initialContext?.toolName,
    pids: opts.initialContext?.pids ?? [],
    meta: opts.initialContext?.meta,
  };

  const capabilities: AgentRuntimeCapabilities = {
    canBlockToolCall: false,
    canTerminateProcess: false,
    platform: detectPlatform(),
    ...opts.capabilities,
  };

  const stateDir =
    opts.stateDir ?? path.join(os.tmpdir(), "agent-aegis-sentinel-noop");

  const shutdownCbs: Array<() => Promise<void>> = [];

  return {
    name: opts.name ?? "noop",
    logger: opts.logger ?? consoleLogger,
    capabilities,
    getCurrentContext: () => ctx,
    onContextChange: () => () => {
      /* never fires */
    },
    registerToolCallInterceptor: (_handler: (a: ToolCallAttempt) => Promise<VerdictApplication>) => {
      /* noop runtime never sees tool calls */
    },
    onShutdown: (cb) => {
      shutdownCbs.push(cb);
    },
    readConfig: async () => opts.config ?? {},
    getStateDir: () => stateDir,
  };
}
