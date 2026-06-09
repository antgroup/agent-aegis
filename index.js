import { definePluginEntry } from "./runtime-api.js";
import { agentAegisPluginConfigDefinition } from "./src/config.js";
import { createAgentAegisRuntime } from "./src/handlers.js";
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
    }
    catch (error) {
        api.logger.error(`[agent-aegis] register failed; fail-open keeps OpenClaw running: ${error instanceof Error ? error.message : String(error)}`);
    }
}
export default definePluginEntry({
    id: "agent-aegis",
    name: "Agent Aegis",
    description: "Minimal safety guard plugin for prompt, tool, and tool-result hardening.",
    configSchema: agentAegisPluginConfigDefinition,
    register(api) {
        registerAgentAegisPlugin(api);
    },
});
