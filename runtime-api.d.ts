export interface OpenClawPluginApi {
    rootDir?: string;
    pluginConfig?: Record<string, unknown>;
    config?: Record<string, unknown>;
    logger: {
        debug?: (msg: string) => void;
        info: (msg: string) => void;
        warn: (msg: string) => void;
        error: (msg: string) => void;
    };
    runtime: {
        state: {
            resolveStateDir: () => string;
        };
    };
    on: (hookName: string, handler: (...args: any[]) => any) => void;
    getPluginConfig: (pluginId: string) => Record<string, unknown> | undefined;
    resolvePath: (p: string) => string;
}
export type OpenClawPluginConfigSchema = Record<string, unknown>;
export type PluginHookMessageContext = {
    sessionKey?: string;
    runId?: string;
    [key: string]: unknown;
};
export type PluginHookGatewayStartEvent = Record<string, never>;
export type PluginHookMessageReceivedEvent = {
    content?: string;
    [key: string]: unknown;
};
export type PluginHookMessageSendingEvent = {
    to: string;
    content: string;
    metadata?: Record<string, unknown>;
};
export type PluginHookMessageSendingResult = {
    content?: string;
    cancel?: boolean;
};
export type PluginHookBeforePromptBuildEvent = {
    prompt?: string;
    messages?: unknown[];
    [key: string]: unknown;
};
export type PluginHookBeforePromptBuildResult = {
    prependContext?: string;
    appendContext?: string;
    prependSystemContext?: string;
    appendSystemContext?: string;
};
export type PluginHookBeforeToolCallEvent = {
    toolName: string;
    params?: Record<string, unknown>;
};
export type PluginHookBeforeToolCallResult = {
    block?: boolean;
    blockReason?: string;
};
export type PluginHookAfterToolCallEvent = {
    toolName: string;
    params?: Record<string, unknown>;
    result?: unknown;
    error?: string;
    durationMs?: number;
    [key: string]: unknown;
};
export type PluginHookBeforeMessageWriteEvent = {
    message: Record<string, unknown>;
};
export type PluginHookBeforeMessageWriteResult = {
    block?: boolean;
    message?: Record<string, unknown>;
};
export type PluginHookAgentEndEvent = {
    messages?: unknown[];
    success?: boolean;
    error?: string;
    durationMs?: number;
    [key: string]: unknown;
};
export type PluginHookSessionEndEvent = {
    sessionId?: string;
    sessionKey?: string;
    messageCount?: number;
    durationMs?: number;
    [key: string]: unknown;
};
type CompatiblePluginKind = "memory" | "context-engine";
type CompatiblePluginEntry = {
    id: string;
    name: string;
    description: string;
    kind?: CompatiblePluginKind;
    configSchema?: OpenClawPluginConfigSchema;
    register: (api: OpenClawPluginApi) => void | Promise<void>;
};
type DefinePluginEntryOptions = CompatiblePluginEntry & {
    configSchema?: OpenClawPluginConfigSchema | (() => OpenClawPluginConfigSchema);
};
export declare function definePluginEntry({ id, name, description, kind, configSchema, register, }: DefinePluginEntryOptions): CompatiblePluginEntry;
export {};
