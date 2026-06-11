import { type OpenClawPluginApi } from "./runtime-api.js";
import { createAgentAegisRuntime } from "./src/handlers.js";
type GenericHookHandler = (event: any, ctx: any) => any;
export declare function wrapHookFailOpen(api: OpenClawPluginApi, hookName: string, handler: GenericHookHandler): GenericHookHandler;
export declare function wrapSyncHookFailOpen(api: OpenClawPluginApi, hookName: string, handler: GenericHookHandler): GenericHookHandler;
export declare function registerAgentAegisPlugin(api: OpenClawPluginApi, createRuntime?: typeof createAgentAegisRuntime): void;
declare const _default: {
    id: string;
    name: string;
    description: string;
    kind?: "memory" | "context-engine";
    configSchema?: import("./runtime-api.js").OpenClawPluginConfigSchema;
    register: (api: OpenClawPluginApi) => void | Promise<void>;
};
export default _default;
