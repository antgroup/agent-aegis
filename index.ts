import { definePluginEntry, type OpenClawPluginApi } from "./runtime-api.js";
import { clawAegisPluginConfigDefinition } from "./src/config.js";
import { createClawAegisRuntime } from "./src/handlers.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- handlers have heterogeneous signatures; `any` is needed for contravariance
type GenericHookHandler = (event: any, ctx: any) => any;

export function wrapHookFailOpen(
  api: OpenClawPluginApi,
  hookName: string,
  handler: GenericHookHandler,
): GenericHookHandler {
  return async (event, ctx) => {
    try {
      return await handler(event, ctx);
    } catch (error) {
      api.logger.error(
        `[agent-aegis] ${hookName} failed; fail-open keeps OpenClaw running: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return undefined;
    }
  };
}

export function registerClawAegisPlugin(
  api: OpenClawPluginApi,
  createRuntime: typeof createClawAegisRuntime = createClawAegisRuntime,
): void {
  try {
    const runtime = createRuntime(api);
    api.on("gateway_start", wrapHookFailOpen(api, "gateway_start", runtime.hooks.gateway_start));
    api.on(
      "message_received",
      wrapHookFailOpen(api, "message_received", runtime.hooks.message_received),
    );
    api.on(
      "message_sending",
      wrapHookFailOpen(api, "message_sending", runtime.hooks.message_sending),
    );
    api.on(
      "before_prompt_build",
      wrapHookFailOpen(api, "before_prompt_build", runtime.hooks.before_prompt_build),
    );
    api.on(
      "before_dispatch",
      wrapHookFailOpen(api, "before_dispatch", runtime.hooks.before_dispatch),
    );
    api.on(
      "before_agent_reply",
      wrapHookFailOpen(api, "before_agent_reply", runtime.hooks.before_agent_reply),
    );
    api.on(
      "before_tool_call",
      wrapHookFailOpen(api, "before_tool_call", runtime.hooks.before_tool_call),
    );
    api.on(
      "after_tool_call",
      wrapHookFailOpen(api, "after_tool_call", runtime.hooks.after_tool_call),
    );
    api.on(
      "before_message_write",
      wrapHookFailOpen(api, "before_message_write", runtime.hooks.before_message_write),
    );
    api.on("llm_output", wrapHookFailOpen(api, "llm_output", runtime.hooks.llm_output));
    api.on("agent_end", wrapHookFailOpen(api, "agent_end", runtime.hooks.agent_end));
    api.on("session_end", wrapHookFailOpen(api, "session_end", runtime.hooks.session_end));
  } catch (error) {
    api.logger.error(
      `[agent-aegis] register failed; fail-open keeps OpenClaw running: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

export default definePluginEntry({
  id: "agent-aegis",
  name: "Agent Aegis",
  description: "Multi-layer runtime safety guard plugin for OpenClaw (prompt, tool, tool-result, memory, skill, and output protection).",
  configSchema: clawAegisPluginConfigDefinition,
  register(api: OpenClawPluginApi) {
    registerClawAegisPlugin(api);
  },
});
