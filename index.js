import { definePluginEntry } from "./runtime-api.js";
import { clawAegisPluginConfigDefinition } from "./src/config.js";
import { createClawAegisRuntime } from "./src/handlers.js";
import { startSentinel } from "./sentinel/index.js";
import { createL1BridgeJudge } from "./sentinel/judges/l1-bridge.js";
import { createNativeJudge } from "./sentinel/judges/native.js";
import { createEbpfProbe } from "./sentinel/probes/ebpf/index.js";
import { createFridaProbe } from "./sentinel/probes/frida/index.js";
import { createOpenClawRuntime } from "./sentinel/runtime/adapters/openclaw.js";
export function wrapHookFailOpen(api, hookName, handler) {
    return async (event, ctx) => {
        try {
            return await handler(event, ctx);
        }
        catch (error) {
            api.logger.error(`[claw-aegis] ${hookName} failed; fail-open keeps OpenClaw running: ${error instanceof Error ? error.message : String(error)}`);
            return undefined;
        }
    };
}
export function wrapSyncHookFailOpen(api, hookName, handler) {
    return (event, ctx) => {
        try {
            return handler(event, ctx);
        }
        catch (error) {
            api.logger.error(`[claw-aegis] ${hookName} failed; fail-open keeps OpenClaw running: ${error instanceof Error ? error.message : String(error)}`);
            return undefined;
        }
    };
}
export function registerClawAegisPlugin(api, createRuntime = createClawAegisRuntime) {
    try {
        const runtime = createRuntime(api);
        api.on("gateway_start", wrapHookFailOpen(api, "gateway_start", runtime.hooks.gateway_start));
        api.on("message_received", wrapSyncHookFailOpen(api, "message_received", runtime.hooks.message_received));
        api.on("message_sending", wrapHookFailOpen(api, "message_sending", runtime.hooks.message_sending));
        api.on("before_prompt_build", wrapHookFailOpen(api, "before_prompt_build", runtime.hooks.before_prompt_build));
        api.on("before_dispatch", wrapHookFailOpen(api, "before_dispatch", runtime.hooks.before_dispatch));
        api.on("before_agent_reply", wrapHookFailOpen(api, "before_agent_reply", runtime.hooks.before_agent_reply));
        api.on("before_tool_call", wrapHookFailOpen(api, "before_tool_call", runtime.hooks.before_tool_call));
        api.on("after_tool_call", wrapSyncHookFailOpen(api, "after_tool_call", runtime.hooks.after_tool_call));
        api.on("before_message_write", wrapSyncHookFailOpen(api, "before_message_write", runtime.hooks.before_message_write));
        api.on("llm_output", wrapSyncHookFailOpen(api, "llm_output", runtime.hooks.llm_output));
        api.on("agent_end", wrapSyncHookFailOpen(api, "agent_end", runtime.hooks.agent_end));
        api.on("session_end", wrapSyncHookFailOpen(api, "session_end", runtime.hooks.session_end));
        try {
            void startSentinelForOpenClaw(api, runtime.engine);
        }
        catch (error) {
            api.logger.warn(`[claw-aegis] sentinel startup failed; L1 defense continues: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    catch (error) {
        api.logger.error(`[claw-aegis] register failed; fail-open keeps OpenClaw running: ${error instanceof Error ? error.message : String(error)}`);
    }
}
/**
 * Bootstrap the sentinel subsystem, register its judges, and conditionally
 * attach probes based on user config.
 *
 * Judges registered unconditionally:
 *   - l1-bridge: delegates `tool_call` syscall events back to the existing
 *     AegisDefenseEngine. Dormant until a probe emits `tool_call`-shaped
 *     events.
 *   - native:    handles syscall events that L1 cannot see (e.g. /etc/shadow
 *     access via execve). Lights up the moment a probe lands.
 *
 * Probes (opt-in):
 *   - frida:     attached only when `probes.frida.enabled === true` in user
 *                config. Always logs a warn on failure rather than throwing.
 */
async function startSentinelForOpenClaw(api, engine) {
    const runtime = createOpenClawRuntime(api);
    const sentinel = startSentinel(runtime);
    sentinel.registerJudge(createL1BridgeJudge(engine));
    sentinel.registerJudge(createNativeJudge());
    try {
        const config = await runtime.readConfig();
        const fridaCfg = readFridaConfig(config);
        if (fridaCfg.enabled) {
            await sentinel.registerProbe(createFridaProbe({
                targets: fridaCfg.targets,
                mode: fridaCfg.mode,
                enforceTimeoutMs: fridaCfg.enforceTimeoutMs,
            }));
        }
        const ebpfCfg = readEbpfConfig(config);
        if (ebpfCfg.enabled) {
            await sentinel.registerProbe(createEbpfProbe({
                pythonBin: ebpfCfg.pythonBin,
                runnerScript: ebpfCfg.runnerScript,
            }));
        }
    }
    catch (err) {
        api.logger.warn(`[claw-aegis] probe wiring failed; sentinel keeps running: ${String(err)}`);
    }
    return sentinel;
}
function readFridaConfig(config) {
    const probes = (config.probes ?? {});
    const frida = (probes.frida ?? {});
    const enabled = frida.enabled === true;
    const rawTargets = frida.targets;
    const targets = Array.isArray(rawTargets)
        ? rawTargets.filter((t) => t === "execve" || t === "openat" || t === "connect")
        : undefined;
    const mode = frida.mode === "enforce" ? "enforce" : frida.mode === "observe" ? "observe" : undefined;
    const enforceTimeoutMs = typeof frida.enforceTimeoutMs === "number" && frida.enforceTimeoutMs > 0
        ? frida.enforceTimeoutMs
        : undefined;
    return { enabled, targets, mode, enforceTimeoutMs };
}
function readEbpfConfig(config) {
    const probes = (config.probes ?? {});
    const ebpf = (probes.ebpf ?? {});
    const enabled = ebpf.enabled === true;
    const pythonBin = typeof ebpf.pythonBin === "string" ? ebpf.pythonBin : undefined;
    const runnerScript = typeof ebpf.runnerScript === "string" ? ebpf.runnerScript : undefined;
    return { enabled, pythonBin, runnerScript };
}
export default definePluginEntry({
    id: "claw-aegis",
    name: "Claw Aegis",
    description: "Minimal safety guard plugin for prompt, tool, and tool-result hardening.",
    configSchema: clawAegisPluginConfigDefinition,
    register(api) {
        registerClawAegisPlugin(api);
    },
});
