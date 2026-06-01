import type { PluginHookAfterToolCallEvent, PluginHookAgentEndEvent, PluginHookBeforePromptBuildEvent, OpenClawPluginApi, PluginHookBeforeMessageWriteEvent, PluginHookBeforePromptBuildResult, PluginHookBeforeToolCallEvent, PluginHookBeforeToolCallResult, PluginHookMessageSendingEvent, PluginHookMessageSendingResult, PluginHookSessionEndEvent } from "../runtime-api.js";
import { type ToolCallDefenseStrategy } from "./security-strategies.js";
import { SkillScanService } from "./scan-service.js";
import { ClawAegisState } from "./state.js";
export declare function createClawAegisRuntime(api: OpenClawPluginApi, options?: {
    now?: () => number;
    scanRunner?: (request: import("./types.js").SkillScanRequest) => Promise<import("./types.js").SkillScanResult>;
    toolCallDefenseStrategies?: readonly ToolCallDefenseStrategy[];
}): {
    state: ClawAegisState;
    scanService: SkillScanService;
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
            body?: string;
            channel?: string;
            sessionKey?: string;
            senderId?: string;
            isGroup?: boolean;
            timestamp?: number;
        }, ctx: {
            channelId?: string;
            accountId?: string;
            conversationId?: string;
            sessionKey?: string;
            senderId?: string;
        }) => Promise<{
            handled: boolean;
            text?: string;
        } | undefined>;
        before_agent_reply: (event: {
            cleanedBody: string;
        }, ctx: {
            runId?: string;
            agentId?: string;
            sessionKey?: string;
            sessionId?: string;
            workspaceDir?: string;
            trigger?: string;
        }) => Promise<{
            handled: boolean;
            reply?: {
                text: string;
            };
            reason?: string;
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
            runId: string;
            sessionId: string;
            provider: string;
            model: string;
        }, _ctx: {
            sessionKey?: string;
            runId?: string;
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
            message: never;
        } | undefined;
    };
};
