/**
 * RPC method handlers for AgentAegis.
 *
 * This module creates an agent-agnostic runtime that exposes the core
 * security checks as simple request/response methods, without depending
 * on the OpenClaw plugin API.  It is consumed by rpc-server.ts (stdio
 * JSON-RPC bridge) so that Hermes (Python) can call the same detection
 * engine that OpenClaw uses natively.
 */
import path from "node:path";
import os from "node:os";
import { AegisDefenseEngine } from "./src/engine.js";
// ---------------------------------------------------------------------------
// Runtime (delegates to AegisDefenseEngine)
// ---------------------------------------------------------------------------
export class AegisRpcRuntime {
    engine;
    initialized = false;
    constructor() { }
    // -----------------------------------------------------------------------
    // init
    // -----------------------------------------------------------------------
    async init(params) {
        const expandedStateDir = params.stateDir.startsWith("~")
            ? path.join(os.homedir(), params.stateDir.slice(1))
            : params.stateDir;
        const expandedSkillRoots = (params.skillRoots ?? []).map(p => p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p);
        // Create a mock API object for the engine
        const mockApi = {
            rootDir: params.pluginRootDir,
            pluginConfig: params.config,
            logger: {
                debug: (msg, meta) => console.error(`[aegis:rpc:debug] ${msg} ${meta ? JSON.stringify(meta) : ""}`),
                info: (msg, meta) => console.error(`[aegis:rpc:info] ${msg} ${meta ? JSON.stringify(meta) : ""}`),
                warn: (msg, meta) => console.error(`[aegis:rpc:warn] ${msg} ${meta ? JSON.stringify(meta) : ""}`),
                error: (msg, meta) => console.error(`[aegis:rpc:error] ${msg} ${meta ? JSON.stringify(meta) : ""}`),
            },
            runtime: {
                state: {
                    resolveStateDir: () => expandedStateDir,
                },
            },
            // Hermes-specific path resolution: expand ~ and resolve relative to plugin root
            resolvePath: (p) => {
                if (p.startsWith("~")) {
                    return p.replace(/^~/, os.homedir());
                }
                return path.resolve(params.pluginRootDir, p);
            },
        };
        this.engine = new AegisDefenseEngine(mockApi, {
            stateDir: expandedStateDir,
            skillScanRoots: expandedSkillRoots,
        });
        await this.engine.start();
        // If Hermes provided extra roots, register them
        if (params.protectedRoots && params.protectedRoots.length > 0) {
            this.engine.state.setProtectedRoots([
                ...this.engine.state.getProtectedRoots(),
                ...params.protectedRoots,
            ]);
        }
        this.initialized = true;
        this.engine.logger.info("agent-aegis RPC runtime initialized");
        return { ok: true };
    }
    // -----------------------------------------------------------------------
    // API methods (delegating to unified engine)
    // -----------------------------------------------------------------------
    checkUserInput(params) {
        this.ensureInit();
        this.engine.checkUserInput(params.content, params.sessionKey);
        const turnState = params.sessionKey ? this.engine.state.peekPromptState(params.sessionKey) : undefined;
        return { riskFlags: turnState?.userRiskFlags ?? [] };
    }
    async getPromptGuard(params) {
        this.ensureInit();
        const context = await this.engine.buildPromptContext(undefined, params.sessionKey);
        return { context: context ?? null };
    }
    checkBeforeTool(params) {
        this.ensureInit();
        const result = this.engine.checkToolCall(params.tool, params.args, params.runId, params.sessionKey);
        if (result) {
            return {
                block: result.block,
                defense: result.defense,
                reason: result.reason,
                details: {},
            };
        }
        return { block: false };
    }
    checkToolResult(params) {
        this.ensureInit();
        const message = { role: "toolResult", toolName: params.tool, content: params.result };
        this.engine.scanToolResult(message, params.sessionKey);
        const turnState = params.sessionKey ? this.engine.state.peekPromptState(params.sessionKey) : undefined;
        return {
            riskFlags: turnState?.toolResultRiskFlags ?? [],
            suspicious: turnState?.toolResultSuspicious ?? false,
        };
    }
    checkLlmOutput(params) {
        this.ensureInit();
        this.engine.handleLlmOutput(params.texts, params.model, params.provider);
        return { ok: true };
    }
    redactOutput(params) {
        this.ensureInit();
        const result = this.engine.redactAssistantMessage({ role: "assistant", content: params.text }, params.sessionKey);
        if (result) {
            return { text: result.message.content, redacted: result.changed };
        }
        return { text: params.text, redacted: false };
    }
    updateState(params) {
        this.ensureInit();
        const sessionKey = params.sessionKey ?? "default";
        const runId = params.runId ?? "unknown";
        switch (params.method) {
            case "clear_session":
                this.engine.state.clearSessionRuntimeState(sessionKey);
                break;
            case "clear_run":
                this.engine.state.clearRunToolCalls(runId);
                this.engine.state.clearRunSecurityState(runId);
                break;
            case "note_user_input":
                if (typeof params.data?.content === "string") {
                    this.engine.state.noteLastUserInput(sessionKey, params.data.content);
                }
                break;
        }
        return { ok: true };
    }
    async scanSkills(params) {
        this.ensureInit();
        await this.engine.scanService.scanRoots({ roots: params.roots });
        await this.engine.state.persistTrustedSkills();
        return { scanned: params.roots.length };
    }
    async dispatch(request) {
        const { id, method, params = {} } = request;
        try {
            let result;
            switch (method) {
                case "init":
                    result = await this.init(params);
                    break;
                case "check_user_input":
                    result = this.checkUserInput(params);
                    break;
                case "get_prompt_guard":
                    result = await this.getPromptGuard(params);
                    break;
                case "check_before_tool":
                    result = this.checkBeforeTool(params);
                    break;
                case "check_tool_result":
                    result = this.checkToolResult(params);
                    break;
                case "check_llm_output":
                    result = this.checkLlmOutput(params);
                    break;
                case "redact_output":
                    result = this.redactOutput(params);
                    break;
                case "update_state":
                    result = this.updateState(params);
                    break;
                case "get_config":
                    result = this.engine.config;
                    break;
                case "scan_skills":
                    result = await this.scanSkills(params);
                    break;
                case "ping":
                    result = { pong: true, initialized: this.initialized };
                    break;
                default:
                    return { id, error: { message: `Unknown method: ${method}`, code: -32601 } };
            }
            return { id, result };
        }
        catch (err) {
            const message = err instanceof Error ? err.message : String(err);
            console.error(`RPC method ${method} failed: ${message}`);
            return { id, error: { message, code: -32000 } };
        }
    }
    ensureInit() {
        if (!this.initialized) {
            throw new Error("AegisRpcRuntime not initialized — call init first");
        }
    }
}
