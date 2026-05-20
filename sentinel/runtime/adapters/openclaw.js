import fs from "node:fs";
import path from "node:path";
export function createOpenClawRuntime(api, opts = {}) {
    const logger = wrapLogger(api.logger);
    const pluginId = opts.pluginId ?? "claw-aegis";
    const stateSubdir = opts.stateSubdir ?? "sentinel";
    const ctx = {
        sessionKey: "default",
        pids: [process.pid],
    };
    const contextSubscribers = new Set();
    const shutdownCallbacks = [];
    // Sentinel registers its tool-call interceptor here; M3 stores it but
    // never invokes it — see SENTINEL_M3_PLAN.md §1 (canBlockToolCall=false).
    // Kept for forward compatibility: a future milestone can flip the
    // capability and start delivering tool-call attempts via this handler.
    let _pendingInterceptor = null;
    function notifyContext() {
        for (const cb of contextSubscribers) {
            try {
                cb(ctx);
            }
            catch (err) {
                logger.warn(`sentinel context subscriber threw: ${String(err)}`);
            }
        }
    }
    function safeOn(hook, handler) {
        api.on(hook, (event, hookCtx) => {
            try {
                handler(event, hookCtx);
            }
            catch (err) {
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
        if (runId)
            ctx.runId = runId;
        if (toolName)
            ctx.toolName = toolName;
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
    const capabilities = {
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
            const merged = { ...(api.pluginConfig ?? {}) };
            const manifestRoot = api.rootDir;
            if (manifestRoot) {
                try {
                    const raw = fs.readFileSync(path.join(manifestRoot, "openclaw.plugin.json"), "utf-8");
                    const parsed = JSON.parse(raw);
                    const fromManifest = parsed.userConfig ?? {};
                    for (const k of Object.keys(fromManifest)) {
                        if (!(k in merged))
                            merged[k] = fromManifest[k];
                    }
                }
                catch (err) {
                    logger.debug(`could not read manifest userConfig: ${String(err)}`);
                }
            }
            return merged;
        },
        getStateDir: () => stateDir,
    };
}
function wrapLogger(raw) {
    const fold = (fn) => (msg, ...args) => {
        fn(args.length === 0 ? msg : `${msg} ${args.map(stringify).join(" ")}`);
    };
    return {
        debug: fold(raw.debug ?? raw.info),
        info: fold(raw.info),
        warn: fold(raw.warn),
        error: fold(raw.error),
    };
}
function stringify(v) {
    if (v === null || v === undefined)
        return String(v);
    if (typeof v === "string")
        return v;
    try {
        return JSON.stringify(v);
    }
    catch {
        return String(v);
    }
}
function detectPlatform() {
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
function readSessionKey(hookCtx) {
    if (!hookCtx || typeof hookCtx !== "object")
        return undefined;
    const v = hookCtx.sessionKey;
    return typeof v === "string" ? v : undefined;
}
function readRunId(hookCtx) {
    if (!hookCtx || typeof hookCtx !== "object")
        return undefined;
    const v = hookCtx.runId;
    return typeof v === "string" ? v : undefined;
}
function readToolName(event) {
    if (!event || typeof event !== "object")
        return undefined;
    const v = event.toolName;
    return typeof v === "string" ? v : undefined;
}
