import type { PluginHookAfterToolCallEvent, PluginHookAgentEndEvent, PluginHookBeforePromptBuildEvent, OpenClawPluginApi, PluginHookBeforeMessageWriteEvent, PluginHookBeforePromptBuildResult, PluginHookBeforeToolCallEvent, PluginHookBeforeToolCallResult, PluginHookMessageSendingEvent, PluginHookMessageSendingResult, PluginHookSessionEndEvent } from "../runtime-api.js";
import { type AegisEngineOptions } from "./engine.js";
export declare function createAgentAegisRuntime(api: OpenClawPluginApi, options?: AegisEngineOptions): {
    state: import("./state.js").AgentAegisState;
    scanService: import("./scan-service.js").SkillScanService;
    hooks: {
        gateway_start: () => Promise<void>;
        message_received: (event: {
            content: string;
        }, ctx: {
            sessionKey?: string;
        }) => void;
        message_sending: (event: PluginHookMessageSendingEvent, ctx: {
            sessionKey?: string;
        }) => PluginHookMessageSendingResult | undefined;
        before_prompt_build: (event: PluginHookBeforePromptBuildEvent, ctx: {
            sessionKey?: string;
        }) => Promise<PluginHookBeforePromptBuildResult | undefined>;
        before_dispatch: (event: {
            content: string;
        }, ctx: {
            sessionKey?: string;
        }) => Promise<{
            block: boolean;
            reason?: string;
            text?: string;
        } | undefined>;
        before_agent_reply: (event: {
            cleanedBody: string;
        }, ctx: {
            sessionKey?: string;
        }) => Promise<{
            handled: boolean;
            reply: {
                text: string;
            };
            reason: string;
        } | undefined>;
        before_tool_call: (event: PluginHookBeforeToolCallEvent, ctx: {
            sessionKey?: string;
            runId?: string;
        }) => PluginHookBeforeToolCallResult | undefined;
        after_tool_call: (event: PluginHookAfterToolCallEvent, ctx: {
            sessionKey?: string;
            runId?: string;
        }) => void;
        llm_output: (event: {
            assistantTexts: string[];
            model: string;
            provider: string;
        }) => void;
        agent_end: (_event: PluginHookAgentEndEvent, ctx: {
            sessionKey?: string;
            runId?: string;
        }) => void;
        session_end: (_event: PluginHookSessionEndEvent, ctx: {
            sessionKey?: string;
        }) => void;
        before_message_write: (event: PluginHookBeforeMessageWriteEvent, ctx: {
            sessionKey?: string;
        }) => {
            message: any;
        } | undefined;
    };
};
