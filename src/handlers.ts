import type {
  PluginHookAfterToolCallEvent,
  PluginHookAgentEndEvent,
  PluginHookBeforePromptBuildEvent,
  OpenClawPluginApi,
  PluginHookBeforeMessageWriteEvent,
  PluginHookBeforePromptBuildResult,
  PluginHookBeforeToolCallEvent,
  PluginHookBeforeToolCallResult,
  PluginHookMessageSendingEvent,
  PluginHookMessageSendingResult,
  PluginHookSessionEndEvent,
} from "../runtime-api.js";
import { AegisDefenseEngine, type AegisEngineOptions } from "./engine.js";

function warnIfPromptHooksDisabled(api: OpenClawPluginApi): void {
  const pluginEntry = ((
    api.config as {
      plugins?: {
        entries?: Record<string, { hooks?: { allowPromptInjection?: boolean } }>;
      };
    }
  ).plugins?.entries ?? {})["claw-aegis"];
  if (pluginEntry?.hooks?.allowPromptInjection === false) {
    api.logger.warn(
      '安全插件配置中已关闭提示词注入 hook，提示防护将不会运行',
    );
  }
}

export function createClawAegisRuntime(
  api: OpenClawPluginApi,
  options?: AegisEngineOptions,
) {
  const engine = new AegisDefenseEngine(api, options);
  warnIfPromptHooksDisabled(api);

  return {
    engine,
    state: engine.state,
    scanService: engine.scanService,
    hooks: {
      gateway_start: async () => {
        await engine.start();
      },

      message_received: (event: { content: string }, ctx: { sessionKey?: string }) => {
        engine.checkUserInput(event.content, ctx.sessionKey);
      },

      message_sending: (
        event: PluginHookMessageSendingEvent,
        ctx: { sessionKey?: string },
      ): PluginHookMessageSendingResult | undefined => {
        const redacted = engine.redactOutboundMessage(event.content, event.to, ctx.sessionKey);
        return redacted ? { content: redacted } : undefined;
      },

      before_prompt_build: async (
        event: PluginHookBeforePromptBuildEvent,
        ctx: { sessionKey?: string },
      ): Promise<PluginHookBeforePromptBuildResult | undefined> => {
        const prependSystemContext = await engine.buildPromptContext(event.prompt, ctx.sessionKey);
        return prependSystemContext ? { prependSystemContext } : undefined;
      },

      before_dispatch: async (
        event: { content: string },
        ctx: { sessionKey?: string },
      ) => {
        return engine.checkDispatch(event.content, ctx.sessionKey, "before_dispatch");
      },

      before_agent_reply: async (
        event: { cleanedBody: string },
        ctx: { sessionKey?: string },
      ) => {
        const result = engine.checkDispatch(event.cleanedBody, ctx.sessionKey, "before_agent_reply");
        if (result?.block) {
          return { handled: true, reply: { text: result.text || "" }, reason: "dispatch_guard" };
        }
        return undefined;
      },

      before_tool_call: (
        event: PluginHookBeforeToolCallEvent,
        ctx: { sessionKey?: string; runId?: string },
      ): PluginHookBeforeToolCallResult | undefined => {
        const result = engine.checkToolCall(event.toolName, event.params ?? {}, ctx.runId, ctx.sessionKey);
        return result?.block ? { block: true, blockReason: result.reason } : undefined;
      },

      after_tool_call: (
        event: PluginHookAfterToolCallEvent,
        ctx: { sessionKey?: string; runId?: string },
      ) => {
        engine.trackToolCallResult(event.toolName, event.params ?? {}, event.error, ctx.runId, ctx.sessionKey);
      },

      llm_output: (
        event: { assistantTexts: string[]; model: string; provider: string },
      ) => {
        engine.handleLlmOutput(event.assistantTexts, event.model, event.provider);
      },

      agent_end: (
        _event: PluginHookAgentEndEvent,
        ctx: { sessionKey?: string; runId?: string },
      ) => {
        if (ctx.runId) {
          engine.state.clearRunToolCalls(ctx.runId);
          engine.state.clearRunSecurityState(ctx.runId);
        }
        if (ctx.sessionKey) {
          engine.state.clearSessionRuntimeState(ctx.sessionKey);
        }
        engine.logger.info("claw-aegis: 已清理本轮临时安全状态", {
          event: "agent_runtime_state_cleared",
          hook: "agent_end",
          sessionKey: ctx.sessionKey,
          runId: ctx.runId,
        });
      },

      session_end: (
        _event: PluginHookSessionEndEvent,
        ctx: { sessionKey?: string },
      ) => {
        if (ctx.sessionKey) {
          engine.state.clearSessionRuntimeState(ctx.sessionKey);
          engine.logger.info("claw-aegis: 已清理 session 级临时安全状态", {
            event: "session_runtime_state_cleared",
            hook: "session_end",
            sessionKey: ctx.sessionKey,
          });
        }
      },

      before_message_write: (
        event: PluginHookBeforeMessageWriteEvent,
        ctx: { sessionKey?: string },
      ) => {
        const message = event.message as Record<string, unknown>;
        if (message.role === "assistant") {
          const result = engine.redactAssistantMessage(message, ctx.sessionKey);
          return result ? { message: result.message as any } : undefined;
        }
        const result = engine.scanToolResult(message, ctx.sessionKey);
        return result ? { message: result.message as any } : undefined;
      },
    },
  };
}

