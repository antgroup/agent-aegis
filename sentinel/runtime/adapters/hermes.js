const stderrLogger = {
    debug: (m, ...a) => process.stderr.write(`[sentinel.hermes] DEBUG ${format(m, a)}\n`),
    info: (m, ...a) => process.stderr.write(`[sentinel.hermes] INFO  ${format(m, a)}\n`),
    warn: (m, ...a) => process.stderr.write(`[sentinel.hermes] WARN  ${format(m, a)}\n`),
    error: (m, ...a) => process.stderr.write(`[sentinel.hermes] ERROR ${format(m, a)}\n`),
};
function format(msg, args) {
    if (args.length === 0)
        return msg;
    const parts = args.map((a) => {
        try {
            return typeof a === "string" ? a : JSON.stringify(a);
        }
        catch {
            return String(a);
        }
    });
    return `${msg} ${parts.join(" ")}`;
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
export function createHermesRuntime(opts) {
    const ctx = {
        sessionKey: opts.initialContext?.sessionKey ?? "default",
        runId: opts.initialContext?.runId,
        toolName: opts.initialContext?.toolName,
        pids: opts.initialContext?.pids ?? [process.pid],
        meta: opts.initialContext?.meta,
    };
    const logger = opts.logger ?? stderrLogger;
    const subscribers = new Set();
    const shutdownCbs = [];
    let shuttingDown = false;
    const capabilities = {
        canBlockToolCall: false,
        canTerminateProcess: false,
        platform: detectPlatform(),
        ...opts.capabilities,
    };
    const runtime = {
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
        registerToolCallInterceptor: (_handler) => {
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
    function pushContext(update) {
        if (update.sessionKey !== undefined)
            ctx.sessionKey = update.sessionKey;
        if ("runId" in update)
            ctx.runId = update.runId;
        if ("toolName" in update)
            ctx.toolName = update.toolName;
        if (update.pids !== undefined)
            ctx.pids = [...update.pids];
        if (update.meta !== undefined)
            ctx.meta = update.meta;
        for (const cb of subscribers) {
            try {
                cb(ctx);
            }
            catch (err) {
                logger.warn(`pushContext subscriber threw: ${String(err)}`);
            }
        }
    }
    async function signalShutdown() {
        if (shuttingDown)
            return;
        shuttingDown = true;
        for (const cb of shutdownCbs) {
            try {
                await cb();
            }
            catch (err) {
                logger.warn(`onShutdown callback threw: ${String(err)}`);
            }
        }
    }
    return { runtime, pushContext, signalShutdown };
}
