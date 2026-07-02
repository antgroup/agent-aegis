import { type AgentAegisPluginConfig } from "./config.js";
import { type ToolCallDefenseStrategy } from "./security-strategies.js";
import { SkillScanService } from "./scan-service.js";
import { AgentAegisState } from "./state.js";
import type { AegisLogger } from "./types.js";
export type AegisEngineOptions = {
    now?: () => number;
    scanRunner?: (request: import("./types.js").SkillScanRequest) => Promise<import("./types.js").SkillScanResult>;
    toolCallDefenseStrategies?: readonly ToolCallDefenseStrategy[];
    stateDir?: string;
    skillScanRoots?: string[];
};
export type DefenseLogMeta = {
    hook: string;
    mechanism: string;
    sessionKey?: string;
    runId?: string;
    toolName?: string;
    durationMs?: number;
    result?: string;
    [key: string]: unknown;
};
export type DefenseEventRecord = {
    timestamp: number;
    defense: string;
    result: "blocked" | "observed";
    toolName?: string;
    reason?: string;
    details?: Record<string, unknown>;
    commandText?: string;
    toolParams?: Record<string, unknown>;
    userInput?: string;
};
export declare class AegisDefenseEngine {
    private readonly api;
    readonly state: AgentAegisState;
    readonly scanService: SkillScanService;
    readonly logger: AegisLogger;
    readonly config: AgentAegisPluginConfig;
    readonly stateDir: string;
    readonly skillScanRoots: string[];
    readonly now: () => number;
    readonly emitDefenseEvent: (record: DefenseEventRecord) => void;
    readonly staticSystemContext: string | undefined;
    private readonly toolCallDefenseStrategies;
    constructor(api: {
        rootDir?: string;
        pluginConfig?: Record<string, unknown>;
        config?: Record<string, unknown>;
        logger: AegisLogger;
        runtime: {
            state: {
                resolveStateDir: () => string;
            };
        };
        resolvePath: (p: string) => string;
    }, options?: AegisEngineOptions);
    start(): Promise<void>;
    checkUserInput(content: string, sessionKey?: string): void;
    redactOutboundMessage(content: string, to: string, sessionKey?: string): string | undefined;
    buildPromptContext(prompt?: string, sessionKey?: string): Promise<string | undefined>;
    checkDispatch(content: string, sessionKey?: string, hookName?: string): {
        block: boolean;
        reason?: string;
        text?: string;
    } | undefined;
    checkToolCall(toolName: string, params: Record<string, unknown>, runId?: string, sessionKey?: string): {
        block: boolean;
        reason?: string;
        defense?: string;
    } | undefined;
    trackToolCallResult(toolName: string, params: Record<string, unknown>, error?: string, runId?: string, sessionKey?: string): void;
    handleLlmOutput(texts: string[], model: string, provider: string): void;
    redactAssistantMessage(message: Record<string, unknown>, sessionKey?: string): {
        message: Record<string, unknown>;
        changed: boolean;
    } | undefined;
    scanToolResult(message: Record<string, unknown>, sessionKey?: string): {
        message: Record<string, unknown>;
        changed: boolean;
    } | undefined;
    private finishCheck;
    private collectTriggeredFlags;
}
