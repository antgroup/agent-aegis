import { AegisDefenseEngine } from "./engine.js";
function warnIfPromptHooksDisabled(api) {
    const pluginEntry = (api.config.plugins?.entries ?? {})["agent-aegis"];
    if (pluginEntry?.hooks?.allowPromptInjection === false) {
        api.logger.warn('安全插件配置中已关闭提示词注入 hook，提示防护将不会运行');
    }
}
export function createAgentAegisRuntime(api, options) {
    const engine = new AegisDefenseEngine(api, options);
    warnIfPromptHooksDisabled(api);
    return {
        state: engine.state,
        scanService: engine.scanService,
        hooks: {
            gateway_start: async () => {
                await engine.start();
            },
            message_received: (event, ctx) => {
                engine.checkUserInput(event.content, ctx.sessionKey);
            },
            message_sending: (event, ctx) => {
                const redacted = engine.redactOutboundMessage(event.content, event.to, ctx.sessionKey);
                return redacted ? { content: redacted } : undefined;
            },
            before_prompt_build: async (event, ctx) => {
                const prependSystemContext = await engine.buildPromptContext(event.prompt, ctx.sessionKey);
                return prependSystemContext ? { prependSystemContext } : undefined;
            },
            before_dispatch: async (event, ctx) => {
                return engine.checkDispatch(event.content, ctx.sessionKey, "before_dispatch");
            },
            before_agent_reply: async (event, ctx) => {
                const result = engine.checkDispatch(event.cleanedBody, ctx.sessionKey, "before_agent_reply");
                if (result?.block) {
                    return { handled: true, reply: { text: result.text || "" }, reason: "dispatch_guard" };
                }
                return undefined;
            },
            before_tool_call: (event, ctx) => {
                const result = engine.checkToolCall(event.toolName, event.params ?? {}, ctx.runId, ctx.sessionKey);
                return result?.block ? { block: true, blockReason: result.reason } : undefined;
            },
            after_tool_call: (event, ctx) => {
                engine.trackToolCallResult(event.toolName, event.params ?? {}, event.error, ctx.runId, ctx.sessionKey);
            },
            llm_output: (event) => {
                engine.handleLlmOutput(event.assistantTexts, event.model, event.provider);
            },
            agent_end: (_event, ctx) => {
                if (ctx.runId) {
                    engine.state.clearRunToolCalls(ctx.runId);
                    engine.state.clearRunSecurityState(ctx.runId);
                }
                if (ctx.sessionKey) {
                    engine.state.clearSessionRuntimeState(ctx.sessionKey);
                }
                engine.logger.info("agent-aegis: 已清理本轮临时安全状态", {
                    event: "agent_runtime_state_cleared",
                    hook: "agent_end",
                    sessionKey: ctx.sessionKey,
                    runId: ctx.runId,
                });
            },
            session_end: (_event, ctx) => {
                if (ctx.sessionKey) {
                    engine.state.clearSessionRuntimeState(ctx.sessionKey);
                    engine.logger.info("agent-aegis: 已清理 session 级临时安全状态", {
                        event: "session_runtime_state_cleared",
                        hook: "session_end",
                        sessionKey: ctx.sessionKey,
                    });
                }
            },
            before_message_write: (event, ctx) => {
                const message = event.message;
                if (message.role === "assistant") {
                    const result = engine.redactAssistantMessage(message, ctx.sessionKey);
                    return result ? { message: result.message } : undefined;
                }
                const result = engine.scanToolResult(message, ctx.sessionKey);
                return result ? { message: result.message } : undefined;
            },
        },
    };
}
