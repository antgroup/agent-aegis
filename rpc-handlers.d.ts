/**
 * RPC method handlers for AgentAegis.
 *
 * This module creates an agent-agnostic runtime that exposes the core
 * security checks as simple request/response methods, without depending
 * on the OpenClaw plugin API.  It is consumed by rpc-server.ts (stdio
 * JSON-RPC bridge) so that Hermes (Python) can call the same detection
 * engine that OpenClaw uses natively.
 */
import { type AgentAegisPluginConfig } from "./src/config.js";
export type RpcRequest = {
    id: number | string;
    method: string;
    params?: Record<string, unknown>;
};
export type RpcResponse = {
    id: number | string;
    result?: unknown;
    error?: {
        message: string;
        code?: number;
    };
};
type CheckBeforeToolParams = {
    tool: string;
    args: Record<string, unknown>;
    sessionKey?: string;
    runId?: string;
};
export declare class AegisRpcRuntime {
    private engine;
    private initialized;
    private hermes?;
    private sentinel?;
    constructor();
    init(params: {
        config: Partial<AgentAegisPluginConfig>;
        stateDir: string;
        pluginRootDir: string;
        skillRoots?: string[];
        protectedRoots?: string[];
    }): Promise<{
        ok: true;
    }>;
    /** Update the live agent context (session/run/pids) the probes label events with. */
    pushContext(params: {
        sessionKey?: string;
        runId?: string;
        toolName?: string;
        pids?: number[];
    }): {
        ok: true;
    };
    /** Tear down sentinel + its probes. Called by rpc-server on SIGTERM/SIGINT. */
    stop(): Promise<void>;
    checkUserInput(params: {
        content: string;
        sessionKey?: string;
    }): {
        riskFlags: string[];
    };
    getPromptGuard(params: {
        sessionKey?: string;
    }): Promise<{
        context: string | null;
    }>;
    checkBeforeTool(params: CheckBeforeToolParams): {
        block: boolean;
        defense?: string;
        reason?: string;
        details?: any;
    };
    checkToolResult(params: {
        tool: string;
        args: Record<string, unknown>;
        result: string;
        sessionKey?: string;
        runId?: string;
    }): {
        riskFlags: string[];
        suspicious: boolean;
    };
    checkLlmOutput(params: {
        texts: string[];
        model: string;
        provider: string;
    }): {
        ok: true;
    };
    redactOutput(params: {
        text: string;
        sessionKey?: string;
    }): {
        text: string;
        redacted: boolean;
    };
    updateState(params: {
        method: string;
        sessionKey?: string;
        runId?: string;
        data?: Record<string, unknown>;
    }): {
        ok: true;
    };
    scanSkills(params: {
        roots: string[];
    }): Promise<{
        scanned: number;
    }>;
    dispatch(request: RpcRequest): Promise<RpcResponse>;
    private ensureInit;
}
export {};
