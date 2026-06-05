import type { ProbeEvent, Verdict } from "../channel/event.js";
import type { Judge } from "./base.js";

/**
 * Structural view of the L1 `AegisDefenseEngine` exposed in `src/engine.ts`.
 *
 * Declared structurally so that sentinel core does NOT need to import the
 * concrete engine type — preserving the rule that `sentinel/judges/` is free
 * of L1 imports. The OpenClaw runtime adapter (M3) constructs the engine and
 * passes it here.
 */
export interface L1EngineLike {
  checkToolCall(
    toolName: string,
    params: Record<string, unknown>,
    runId?: string,
    sessionKey?: string,
  ): { block: boolean; reason?: string; defense?: string } | undefined;
}

const JUDGE_ID = "l1-bridge";

export interface L1BridgeOptions {
  /** Override severity assigned to L1 blocks (defaults to "high"). */
  severity?: Verdict["severity"];
}

/**
 * A Judge that delegates to the existing L1 engine for `tool_call` events.
 *
 * Probe-originated events (eBPF / uprobe / LSM) are NOT routed through L1 — those go
 * to the native judge, which knows how to read syscall args. L1 was designed
 * around tool-call intent and has no concept of an `execve`/`openat` event.
 */
export function createL1BridgeJudge(engine: L1EngineLike, opts: L1BridgeOptions = {}): Judge {
  const severity = opts.severity ?? "high";
  return {
    id: JUDGE_ID,
    async judge(event: ProbeEvent): Promise<Verdict | null> {
      if (event.syscall !== "tool_call") return null;

      const toolName = readString(event.args.toolName) ?? event.toolName;
      if (!toolName) return null;
      const params = readObject(event.args.params);

      let result: ReturnType<L1EngineLike["checkToolCall"]>;
      try {
        result = engine.checkToolCall(toolName, params, event.runId, event.sessionKey);
      } catch (err) {
        // Let aggregator's onJudgeError surface this; abstaining is safer than
        // synthesizing a verdict from an undefined engine state.
        throw err;
      }

      if (!result || !result.block) return null;
      return {
        action: "block",
        severity,
        reason: result.reason ?? "blocked by L1 engine",
        judgeId: result.defense ? `${JUDGE_ID}:${result.defense}` : JUDGE_ID,
        confidence: 1,
      };
    },
  };
}

function readString(v: unknown): string | undefined {
  return typeof v === "string" ? v : undefined;
}

function readObject(v: unknown): Record<string, unknown> {
  return v && typeof v === "object" && !Array.isArray(v) ? (v as Record<string, unknown>) : {};
}
