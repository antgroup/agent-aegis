import { type OpenClawPluginApi } from "./runtime-api.js";
import { createClawAegisRuntime } from "./src/handlers.js";
type GenericHookHandler = (event: any, ctx: any) => any;
export declare function wrapHookFailOpen(api: OpenClawPluginApi, hookName: string, handler: GenericHookHandler): GenericHookHandler;
export declare function registerClawAegisPlugin(api: OpenClawPluginApi, createRuntime?: typeof createClawAegisRuntime): void;
declare const _default: {
    id: string;
    name: string;
    description: string;
    kind?: "memory" | "context-engine";
    configSchema?: import("./runtime-api.js").OpenClawPluginConfigSchema;
    register: (api: OpenClawPluginApi) => void | Promise<void>;
};
export default _default;
