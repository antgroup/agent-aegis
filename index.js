import { definePluginEntry } from "./runtime-api.js";
import { agentAegisPluginConfigDefinition } from "./src/config.js";
import { createAgentAegisRuntime } from "./src/handlers.js";
import { createOpenClawRuntime } from "./sentinel/runtime/adapters/openclaw.js";
import { startSentinelRuntime } from "./sentinel/bootstrap.js";
// Re-exported for unit tests (sentinel/__tests__/index-native-config.test.ts).
export { _internalReadNativeJudgeConfig } from "./sentinel/bootstrap.js";
export function wrapHookFailOpen(api, hookName, handler) {
    return async (event, ctx) => {
        try {
            return await handler(event, ctx);
        }
        catch (error) {
            api.logger.error(`[agent-aegis] ${hookName} failed; fail-open keeps OpenClaw running: ${error instanceof Error ? error.message : String(error)}`);
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
            api.logger.error(`[agent-aegis] ${hookName} failed; fail-open keeps OpenClaw running: ${error instanceof Error ? error.message : String(error)}`);
            return undefined;
        }
    };
}
export function registerAgentAegisPlugin(api, createRuntime = createAgentAegisRuntime) {
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
            api.logger.warn(`[agent-aegis] sentinel startup failed; L1 defense continues: ${error instanceof Error ? error.message : String(error)}`);
        }
    }
    catch (error) {
        api.logger.error(`[agent-aegis] register failed; fail-open keeps OpenClaw running: ${error instanceof Error ? error.message : String(error)}`);
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
 * Probes (opt-in, Linux only):
 *   - ebpf:    syscall tracepoint observer (M5 / system-wide)
 *   - uprobe:  user-space libc/openssl symbol observer (M7)
 *   - lsm:     in-kernel enforce — denies high-severity verdicts (M7.5)
 *
 * All probes log a warn on failure rather than throwing. A legacy
 * `probes.frida.*` block in user config is accepted but no-op'd with a warn —
 * Frida support was removed in M9.
 */
async function startSentinelForOpenClaw(api, engine) {
    return startSentinelRuntime(createOpenClawRuntime(api), engine);
}
export default definePluginEntry({
    id: "agent-aegis",
    name: "Agent Aegis",
    description: "Multi-layer runtime safety guard plugin for OpenClaw (prompt, tool, tool-result, memory, skill, and output protection).",
    configSchema: agentAegisPluginConfigDefinition,
    register(api) {
        registerAgentAegisPlugin(api);
    },
});
