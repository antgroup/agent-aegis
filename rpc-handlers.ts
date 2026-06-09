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

import { type AgentAegisPluginConfig } from "./src/config.js";
import { AegisDefenseEngine } from "./src/engine.js";
import { startSentinelRuntime } from "./sentinel/bootstrap.js";
import {
  createHermesRuntime,
  type HermesRuntimeHandle,
} from "./sentinel/runtime/adapters/hermes.js";
import type { SentinelHandle } from "./sentinel/index.js";

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type RpcRequest = {
  id: number | string;
  method: string;
  params?: Record<string, unknown>;
};

export type RpcResponse = {
  id: number | string;
  result?: unknown;
  error?: { message: string; code?: number };
};

type CheckBeforeToolParams = {
  tool: string;
  args: Record<string, unknown>;
  sessionKey?: string;
  runId?: string;
};

// ---------------------------------------------------------------------------
// Runtime (delegates to AegisDefenseEngine)
// ---------------------------------------------------------------------------

export class AegisRpcRuntime {
  private engine!: AegisDefenseEngine;
  private initialized = false;
  // Sentinel (eBPF/uprobe/LSM kernel-level defense) — started on init when the
  // Hermes config enables a probe. Same subsystem OpenClaw starts in index.ts.
  private hermes?: HermesRuntimeHandle;
  private sentinel?: SentinelHandle;

  constructor() {}

  // -----------------------------------------------------------------------
  // init
  // -----------------------------------------------------------------------

  async init(params: {
    config: Partial<AgentAegisPluginConfig>;
    stateDir: string;
    pluginRootDir: string;
    skillRoots?: string[];
    protectedRoots?: string[];
  }): Promise<{ ok: true }> {
    const expandedStateDir = params.stateDir.startsWith("~")
      ? path.join(os.homedir(), params.stateDir.slice(1))
      : params.stateDir;
    
    const expandedSkillRoots = (params.skillRoots ?? []).map(p => 
      p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p
    );

    // Create a mock API object for the engine
    const mockApi = {
      rootDir: params.pluginRootDir,
      pluginConfig: params.config,
      logger: {
        debug: (msg: string, meta?: any) => console.error(`[aegis:rpc:debug] ${msg} ${meta ? JSON.stringify(meta) : ""}`),
        info: (msg: string, meta?: any) => console.error(`[aegis:rpc:info] ${msg} ${meta ? JSON.stringify(meta) : ""}`),
        warn: (msg: string, meta?: any) => console.error(`[aegis:rpc:warn] ${msg} ${meta ? JSON.stringify(meta) : ""}`),
        error: (msg: string, meta?: any) => console.error(`[aegis:rpc:error] ${msg} ${meta ? JSON.stringify(meta) : ""}`),
      },
      runtime: {
        state: {
          resolveStateDir: () => expandedStateDir,
        },
      },
      // Hermes-specific path resolution: expand ~ and resolve relative to plugin root
      resolvePath: (p: string) => {
        if (p.startsWith("~")) {
          return p.replace(/^~/, os.homedir());
        }
        return path.resolve(params.pluginRootDir, p);
      },
    };

    this.engine = new AegisDefenseEngine(mockApi as any, {
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

    // Start the sentinel subsystem (eBPF/uprobe/LSM probes + native judge) on a
    // Hermes runtime — mirrors OpenClaw's startSentinelForOpenClaw. Probes only
    // attach when the config enables them. FIRE-AND-FORGET on purpose: probe
    // attach takes seconds and bridge.py enforces a short RPC timeout, so init
    // must return promptly. Detections forward to <stateDir>/defense-events.jsonl
    // (the file the Hermes WebUI tails).
    try {
      this.hermes = createHermesRuntime({
        stateDir: expandedStateDir,
        config: params.config as Record<string, unknown>,
      });
      void startSentinelRuntime(this.hermes.runtime, this.engine)
        .then((handle) => {
          this.sentinel = handle;
        })
        .catch((err) => console.error(`[aegis:rpc] sentinel start failed: ${String(err)}`));
    } catch (err) {
      console.error(`[aegis:rpc] sentinel wiring failed; L1 continues: ${String(err)}`);
    }

    this.initialized = true;
    this.engine.logger.info("agent-aegis RPC runtime initialized");
    return { ok: true };
  }

  /** Update the live agent context (session/run/pids) the probes label events with. */
  pushContext(params: {
    sessionKey?: string;
    runId?: string;
    toolName?: string;
    pids?: number[];
  }): { ok: true } {
    this.hermes?.pushContext({
      sessionKey: params.sessionKey,
      runId: params.runId,
      toolName: params.toolName,
      pids: params.pids,
    });
    return { ok: true };
  }

  /** Tear down sentinel + its probes. Called by rpc-server on SIGTERM/SIGINT. */
  async stop(): Promise<void> {
    try {
      await this.sentinel?.stop();
    } catch (err) {
      console.error(`[aegis:rpc] sentinel stop threw: ${String(err)}`);
    }
    try {
      await this.hermes?.signalShutdown();
    } catch (err) {
      console.error(`[aegis:rpc] hermes shutdown threw: ${String(err)}`);
    }
  }

  // -----------------------------------------------------------------------
  // API methods (delegating to unified engine)
  // -----------------------------------------------------------------------

  checkUserInput(params: {
    content: string;
    sessionKey?: string;
  }): { riskFlags: string[] } {
    this.ensureInit();
    this.engine.checkUserInput(params.content, params.sessionKey);
    const turnState = params.sessionKey ? this.engine.state.peekPromptState(params.sessionKey) : undefined;
    return { riskFlags: turnState?.userRiskFlags ?? [] };
  }

  async getPromptGuard(params: {
    sessionKey?: string;
  }): Promise<{ context: string | null }> {
    this.ensureInit();
    const context = await this.engine.buildPromptContext(undefined, params.sessionKey);
    return { context: context ?? null };
  }

  checkBeforeTool(params: CheckBeforeToolParams): { block: boolean; defense?: string; reason?: string; details?: any } {
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

  checkToolResult(params: {
    tool: string;
    args: Record<string, unknown>;
    result: string;
    sessionKey?: string;
    runId?: string;
  }): { riskFlags: string[]; suspicious: boolean } {
    this.ensureInit();
    const message = { role: "toolResult", toolName: params.tool, content: params.result };
    this.engine.scanToolResult(message, params.sessionKey);
    
    const turnState = params.sessionKey ? this.engine.state.peekPromptState(params.sessionKey) : undefined;
    return {
      riskFlags: turnState?.toolResultRiskFlags ?? [],
      suspicious: turnState?.toolResultSuspicious ?? false,
    };
  }

  checkLlmOutput(params: {
    texts: string[];
    model: string;
    provider: string;
  }): { ok: true } {
    this.ensureInit();
    this.engine.handleLlmOutput(params.texts, params.model, params.provider);
    return { ok: true };
  }

  redactOutput(params: {
    text: string;
    sessionKey?: string;
  }): { text: string; redacted: boolean } {
    this.ensureInit();
    const result = this.engine.redactAssistantMessage({ role: "assistant", content: params.text }, params.sessionKey);
    if (result) {
        return { text: result.message.content as string, redacted: result.changed };
    }
    return { text: params.text, redacted: false };
  }

  updateState(params: {
    method: string;
    sessionKey?: string;
    runId?: string;
    data?: Record<string, unknown>;
  }): { ok: true } {
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

  async scanSkills(params: { roots: string[] }): Promise<{ scanned: number }> {
    this.ensureInit();
    await this.engine.scanService.scanRoots({ roots: params.roots });
    await this.engine.state.persistTrustedSkills();
    return { scanned: params.roots.length };
  }

  async dispatch(request: RpcRequest): Promise<RpcResponse> {
    const { id, method, params = {} } = request;
    try {
      let result: unknown;
      switch (method) {
        case "init":
          result = await this.init(params as any);
          break;
        case "check_user_input":
          result = this.checkUserInput(params as any);
          break;
        case "get_prompt_guard":
          result = await this.getPromptGuard(params as any);
          break;
        case "check_before_tool":
          result = this.checkBeforeTool(params as any);
          break;
        case "check_tool_result":
          result = this.checkToolResult(params as any);
          break;
        case "check_llm_output":
          result = this.checkLlmOutput(params as any);
          break;
        case "redact_output":
          result = this.redactOutput(params as any);
          break;
        case "update_state":
          result = this.updateState(params as any);
          break;
        case "push_context":
          result = this.pushContext(params as any);
          break;
        case "get_config":
          result = this.engine.config;
          break;
        case "scan_skills":
          result = await this.scanSkills(params as any);
          break;
        case "ping":
          result = { pong: true, initialized: this.initialized };
          break;
        default:
          return { id, error: { message: `Unknown method: ${method}`, code: -32601 } };
      }
      return { id, result };
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      console.error(`RPC method ${method} failed: ${message}`);
      return { id, error: { message, code: -32000 } };
    }
  }

  private ensureInit(): void {
    if (!this.initialized) {
      throw new Error("AegisRpcRuntime not initialized — call init first");
    }
  }
}
