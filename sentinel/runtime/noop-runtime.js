import os from "node:os";
import path from "node:path";
const consoleLogger = {
    debug: (m, ...a) => console.debug(`[sentinel] ${m}`, ...a),
    info: (m, ...a) => console.info(`[sentinel] ${m}`, ...a),
    warn: (m, ...a) => console.warn(`[sentinel] ${m}`, ...a),
    error: (m, ...a) => console.error(`[sentinel] ${m}`, ...a),
};
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
/**
 * Default in-process AgentRuntime used when sentinel runs without a real
 * agent framework attached — e.g. during unit tests or M1 smoke startup.
 *
 * It never intercepts tool calls, never reports PIDs, and silently swallows
 * shutdown callbacks (the test runner / OpenClaw plugin lifecycle handles
 * teardown).
 */
export function createNoopRuntime(opts = {}) {
    const ctx = {
        sessionKey: opts.initialContext?.sessionKey ?? "noop",
        runId: opts.initialContext?.runId,
        toolName: opts.initialContext?.toolName,
        pids: opts.initialContext?.pids ?? [],
        meta: opts.initialContext?.meta,
    };
    const capabilities = {
        canBlockToolCall: false,
        canTerminateProcess: false,
        platform: detectPlatform(),
        ...opts.capabilities,
    };
    const stateDir = opts.stateDir ?? path.join(os.tmpdir(), "claw-aegis-sentinel-noop");
    const shutdownCbs = [];
    return {
        name: opts.name ?? "noop",
        logger: opts.logger ?? consoleLogger,
        capabilities,
        getCurrentContext: () => ctx,
        onContextChange: () => () => {
            /* never fires */
        },
        registerToolCallInterceptor: (_handler) => {
            /* noop runtime never sees tool calls */
        },
        onShutdown: (cb) => {
            shutdownCbs.push(cb);
        },
        readConfig: async () => opts.config ?? {},
        getStateDir: () => stateDir,
    };
}
