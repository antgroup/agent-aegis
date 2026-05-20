import fs from "node:fs";
import { createProbeEvent } from "../../channel/event.js";
import { parseAgentMessage } from "./messages.js";
import { detectFridaSupport } from "./platform.js";
const PROBE_ID = "frida";
const EVENT_SOURCE = "frida";
/**
 * Build a Frida probe. The probe is observe-only in M4: it ships syscall
 * events to sentinel via `deps.publish` but never blocks the caller.
 *
 * Graceful degradation policy:
 *   - Unsupported platform → log info, return without throwing.
 *   - frida module fails to import → log warn, return without throwing.
 *   - attach / script load fails → log warn, return without throwing.
 *
 * Sentinel's `registerProbe` already swallows throws from `start()`, but the
 * loader logs richer context here so operators get an actionable line.
 */
export function createFridaProbe(opts = {}) {
    const support = opts.platformOverride ?? detectFridaSupport();
    const requestedTargets = opts.targets ?? support.defaultTargets;
    const mode = opts.mode ?? "observe";
    const enforceTimeoutMs = opts.enforceTimeoutMs ?? 200;
    let session = null;
    let script = null;
    let deps = null;
    async function start(d) {
        deps = d;
        const log = d.runtime.logger;
        if (!support.supported) {
            log.info(`[frida] probe skipped: ${support.reason ?? `platform=${support.platform} unsupported`}`);
            return;
        }
        const frida = await loadFrida(opts.fridaModuleOverride, log);
        if (!frida)
            return;
        const scriptSource = opts.agentScriptOverride ?? readAgentScript(support.agentScriptPath, log);
        if (!scriptSource)
            return;
        const pid = opts.attachPid ?? process.pid;
        try {
            session = await frida.attach(pid);
            script = await session.createScript(scriptSource);
            const localScript = script;
            script.message.connect((msg, _data) => {
                try {
                    handleRawMessage(msg, d, {
                        script: localScript,
                        mode,
                        enforceTimeoutMs,
                    });
                }
                catch (err) {
                    log.warn(`[frida] message handler threw: ${String(err)}`);
                }
            });
            await script.load();
            script.post({ type: "configure", targets: requestedTargets, mode });
            log.info(`[frida] attached pid=${pid}, requested=${requestedTargets.join(",")}, mode=${mode}`);
        }
        catch (err) {
            log.warn(`[frida] attach/load failed; probe disabled: ${String(err)}`);
            await teardown(log);
        }
    }
    async function stop() {
        const log = deps?.runtime.logger;
        await teardown(log);
    }
    async function teardown(log) {
        if (script) {
            try {
                await script.unload();
            }
            catch (err) {
                log?.debug(`[frida] script.unload threw: ${String(err)}`);
            }
            script = null;
        }
        if (session) {
            try {
                await session.detach();
            }
            catch (err) {
                log?.debug(`[frida] session.detach threw: ${String(err)}`);
            }
            session = null;
        }
    }
    return { id: PROBE_ID, start, stop };
}
async function loadFrida(override, log) {
    if (override === null) {
        log.warn("[frida] module not installed (override=null); probe disabled");
        return null;
    }
    if (override !== undefined) {
        return override;
    }
    try {
        // Dynamic import keeps `frida` truly optional — declared in
        // optionalDependencies, not in dependencies. Use an indirection through
        // `Function` so TypeScript does not try to resolve the module at build
        // time (it isn't installed in CI / minimal setups).
        const dynamicImport = new Function("name", "return import(name)");
        const mod = (await dynamicImport("frida"));
        if (typeof mod?.attach !== "function") {
            log.warn("[frida] module loaded but missing attach(); disabling probe");
            return null;
        }
        return mod;
    }
    catch (err) {
        log.warn(`[frida] module not installed or failed to load; probe disabled: ${String(err)}`);
        return null;
    }
}
function readAgentScript(filePath, log) {
    try {
        return fs.readFileSync(filePath, "utf8");
    }
    catch (err) {
        log.warn(`[frida] failed to read agent script ${filePath}: ${String(err)}`);
        return null;
    }
}
/**
 * Translate an agent message into a ProbeEvent and publish it. Exported for
 * testing.
 *
 * `enforce` argument is optional so M4 callers (observe-only) still type-check
 * unchanged.
 */
export function handleRawMessage(raw, deps, enforce) {
    // Frida wraps `send(msg)` in `{ type: "send", payload: msg }`.
    const payload = unwrap(raw);
    const parsed = parseAgentMessage(payload);
    if (!parsed)
        return;
    routeMessage(parsed, deps, enforce);
}
function unwrap(raw) {
    if (!raw || typeof raw !== "object")
        return raw;
    const r = raw;
    if (r.type === "send" && r.payload !== undefined)
        return r.payload;
    return raw;
}
function routeMessage(msg, deps, enforce) {
    const log = deps.runtime.logger;
    switch (msg.kind) {
        case "syscall": {
            const event = createProbeEvent({
                source: EVENT_SOURCE,
                syscall: msg.syscall,
                pid: msg.pid,
                timestamp: msg.ts,
                args: buildArgs(msg),
                sessionKey: deps.runtime.getCurrentContext().sessionKey,
                runId: deps.runtime.getCurrentContext().runId,
                toolName: deps.runtime.getCurrentContext().toolName,
            });
            void deps.publish(event);
            return;
        }
        case "log":
            log[msg.level](`[frida.agent] ${msg.message}`);
            return;
        case "error":
            log.warn(`[frida.agent] error in ${msg.where}: ${msg.message}`);
            return;
        case "ready":
            log.info(`[frida.agent] ready; hooks installed: ${msg.hookedTargets.join(",")}`);
            return;
        case "unsupported":
            log.info(`[frida.agent] platform unsupported: ${msg.platform}`);
            return;
        case "decision_request":
            if (enforce)
                void handleDecisionRequest(msg, deps, enforce);
            return;
        case "decision_response":
            // The agent itself receives decision_response via recv(); loader
            // should not see them. Log and drop.
            log.debug(`[frida.agent] unexpected decision_response id=${msg.id}`);
            return;
    }
}
/**
 * Drives the enforce path: publish a ProbeEvent, race the verdict against a
 * timer, post the resulting allow/deny back to the agent. Always responds
 * exactly once (post-once semantics ensured by a settled flag).
 *
 * Fail-open is the rule: timeout, publish throw, or unexpected verdict
 * shape all map to `allow` with a reason — see SENTINEL_M4_5_PLAN.md §3.
 */
async function handleDecisionRequest(req, deps, enforce) {
    const log = deps.runtime.logger;
    let settled = false;
    const respond = (decision, reason) => {
        if (settled)
            return;
        settled = true;
        try {
            enforce.script.post({
                type: "decision_response_" + req.id,
                decision,
                reason,
            });
        }
        catch (err) {
            log.warn(`[frida] failed to post decision response: ${String(err)}`);
        }
    };
    const timer = setTimeout(() => respond("allow", "timeout"), enforce.enforceTimeoutMs);
    try {
        const event = createProbeEvent({
            source: EVENT_SOURCE,
            syscall: req.syscall,
            pid: req.pid,
            args: buildArgs(req),
            sessionKey: deps.runtime.getCurrentContext().sessionKey,
            runId: deps.runtime.getCurrentContext().runId,
            toolName: deps.runtime.getCurrentContext().toolName,
            meta: { enforce: true, requestId: req.id },
        });
        const aggregated = await deps.publish(event);
        if (aggregated && aggregated.final.action === "block") {
            respond("deny", aggregated.final.reason);
        }
        else {
            respond("allow", aggregated?.final.reason ?? "no-block");
        }
    }
    catch (err) {
        log.warn(`[frida] enforce publish threw: ${String(err)}`);
        respond("allow", "publish-error");
    }
    finally {
        clearTimeout(timer);
    }
}
function buildArgs(msg) {
    const out = {};
    if (msg.argv)
        out.argv = msg.argv;
    if (msg.path)
        out.path = msg.path;
    if (msg.addr)
        out.addr = msg.addr;
    if (msg.extra)
        out.extra = msg.extra;
    return out;
}
