import fs from "node:fs";
import path from "node:path";
import type { OpenClawPluginApi } from "../../../runtime-api.js";
import type {
  AgentContext,
  AgentLogger,
  AgentRuntime,
  AgentRuntimeCapabilities,
  ToolCallAttempt,
  VerdictApplication,
} from "../types.js";

/**
 * OpenClaw → sentinel adapter.
 *
 * This is one of the rare files in the repo where it is acceptable to import
 * from both `runtime-api.js` (framework SDK) and the sentinel runtime types.
 * Doing the translation here keeps sentinel core free of framework knowledge.
 */

export interface OpenClawRuntimeOptions {
  /**
   * Sub-namespace under `api.runtime.state.resolveStateDir()`. Defaults to
   * "sentinel" — keeps probe-event JSONLs separate from the rest of
   * ClawAegis's persisted state.
   */
  stateSubdir?: string;
  /** Plugin id used to look up config. Defaults to "claw-aegis". */
  pluginId?: string;
}

export function createOpenClawRuntime(
  api: OpenClawPluginApi,
  opts: OpenClawRuntimeOptions = {},
): AgentRuntime {
  const logger = wrapLogger(api.logger);
  const pluginId = opts.pluginId ?? "claw-aegis";
  const stateSubdir = opts.stateSubdir ?? "sentinel";

  const ctx: AgentContext = {
    sessionKey: "default",
    pids: [process.pid],
  };
  const contextSubscribers = new Set<(c: AgentContext) => void>();
  const shutdownCallbacks: Array<() => Promise<void>> = [];
  // Sentinel registers its tool-call interceptor here; M3 stores it but
  // never invokes it — see SENTINEL_M3_PLAN.md §1 (canBlockToolCall=false).
  // Kept for forward compatibility: a future milestone can flip the
  // capability and start delivering tool-call attempts via this handler.
  let _pendingInterceptor:
    | ((attempt: ToolCallAttempt) => Promise<VerdictApplication>)
    | null = null;

  function notifyContext(): void {
    for (const cb of contextSubscribers) {
      try {
        cb(ctx);
      } catch (err) {
        logger.warn(`sentinel context subscriber threw: ${String(err)}`);
      }
    }
  }

  function safeOn(hook: string, handler: (event: unknown, hookCtx: unknown) => void): void {
    api.on(hook, (event: unknown, hookCtx: unknown) => {
      try {
        handler(event, hookCtx);
      } catch (err) {
        logger.warn(`sentinel openclaw adapter hook ${hook} failed: ${String(err)}`);
      }
    });
  }

  safeOn("message_received", (_event, hookCtx) => {
    const sessionKey = readSessionKey(hookCtx);
    if (sessionKey && sessionKey !== ctx.sessionKey) {
      ctx.sessionKey = sessionKey;
      ctx.runId = undefined;
      ctx.toolName = undefined;
      notifyContext();
    }
  });

  safeOn("before_tool_call", (event, hookCtx) => {
    const toolName = readToolName(event);
    const runId = readRunId(hookCtx);
    if (runId) ctx.runId = runId;
    if (toolName) ctx.toolName = toolName;
    notifyContext();
  });

  safeOn("after_tool_call", () => {
    if (ctx.toolName) {
      ctx.toolName = undefined;
      notifyContext();
    }
  });

  safeOn("session_end", () => {
    if (ctx.sessionKey !== "default" || ctx.runId || ctx.toolName) {
      ctx.sessionKey = "default";
      ctx.runId = undefined;
      ctx.toolName = undefined;
      notifyContext();
    }
  });

  const capabilities: AgentRuntimeCapabilities = {
    canBlockToolCall: false,
    canTerminateProcess: false,
    platform: detectPlatform(),
  };

  const stateDir = path.join(api.runtime.state.resolveStateDir(), stateSubdir);

  return {
    name: "openclaw",
    logger,
    capabilities,
    getCurrentContext: () => ({ ...ctx, pids: [...ctx.pids] }),
    onContextChange: (cb) => {
      contextSubscribers.add(cb);
      return () => {
        contextSubscribers.delete(cb);
      };
    },
    registerToolCallInterceptor: (handler) => {
      _pendingInterceptor = handler;
    },
    onShutdown: (cb) => {
      shutdownCallbacks.push(cb);
    },
    readConfig: async () => {
      // OpenClaw populates api.pluginConfig from the plugin's configSchema,
      // but in our observed behavior (2026.5.7) only fields with a primitive
      // `default:` make it through — nested objects/arrays without a
      // top-level default get dropped even when the user set them. So we
      // augment that view with the plugin manifest's userConfig block read
      // directly from disk, treating it as the lowest-priority defaults.
      // Precedence: api.pluginConfig overrides > manifest userConfig defaults.
      const merged: Record<string, unknown> = { ...(api.pluginConfig ?? {}) };
      const manifestRoot = api.rootDir;
      if (manifestRoot) {
        try {
          const raw = fs.readFileSync(
            path.join(manifestRoot, "openclaw.plugin.json"),
            "utf-8",
          );
          const parsed = JSON.parse(raw) as { userConfig?: Record<string, unknown> };
          const fromManifest = parsed.userConfig ?? {};
          for (const k of Object.keys(fromManifest)) {
            if (!(k in merged)) merged[k] = fromManifest[k];
          }
        } catch (err) {
          logger.debug(`could not read manifest userConfig: ${String(err)}`);
        }
      }
      return merged;
    },
    getStateDir: () => stateDir,
  };
}

function wrapLogger(raw: OpenClawPluginApi["logger"]): AgentLogger {
  const fold = (fn: (m: string) => void) =>
    (msg: string, ...args: unknown[]): void => {
      fn(args.length === 0 ? msg : `${msg} ${args.map(stringify).join(" ")}`);
    };
  return {
    debug: fold(raw.debug ?? raw.info),
    info: fold(raw.info),
    warn: fold(raw.warn),
    error: fold(raw.error),
  };
}

function stringify(v: unknown): string {
  if (v === null || v === undefined) return String(v);
  if (typeof v === "string") return v;
  try {
    return JSON.stringify(v);
  } catch {
    return String(v);
  }
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

function readSessionKey(hookCtx: unknown): string | undefined {
  if (!hookCtx || typeof hookCtx !== "object") return undefined;
  const v = (hookCtx as { sessionKey?: unknown }).sessionKey;
  return typeof v === "string" ? v : undefined;
}

function readRunId(hookCtx: unknown): string | undefined {
  if (!hookCtx || typeof hookCtx !== "object") return undefined;
  const v = (hookCtx as { runId?: unknown }).runId;
  return typeof v === "string" ? v : undefined;
}

function readToolName(event: unknown): string | undefined {
  if (!event || typeof event !== "object") return undefined;
  const v = (event as { toolName?: unknown }).toolName;
  return typeof v === "string" ? v : undefined;
}
