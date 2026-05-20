import { describe, expect, it } from "vitest";
import { createProbeEvent } from "../channel/event.js";
import { createL1BridgeJudge, type L1EngineLike } from "../judges/l1-bridge.js";

function stubEngine(
  result: ReturnType<L1EngineLike["checkToolCall"]>,
  capture?: (args: { toolName: string; params: Record<string, unknown> }) => void,
): L1EngineLike {
  return {
    checkToolCall(toolName, params) {
      capture?.({ toolName, params });
      return result;
    },
  };
}

describe("createL1BridgeJudge", () => {
  it("abstains on non-tool_call syscalls", async () => {
    const judge = createL1BridgeJudge(stubEngine({ block: true, reason: "x" }));
    const ev = createProbeEvent({ source: "frida", syscall: "execve", pid: 1, args: { argv: ["x"] } });
    expect(await judge.judge(ev)).toBeNull();
  });

  it("abstains when L1 engine returns undefined / no block", async () => {
    const judge = createL1BridgeJudge(stubEngine(undefined));
    const ev = createProbeEvent({
      source: "l1-hook",
      syscall: "tool_call",
      pid: 0,
      args: { toolName: "terminal", params: { cmd: "ls" } },
    });
    expect(await judge.judge(ev)).toBeNull();

    const judge2 = createL1BridgeJudge(stubEngine({ block: false }));
    expect(await judge2.judge(ev)).toBeNull();
  });

  it("returns a block verdict when L1 engine blocks", async () => {
    const judge = createL1BridgeJudge(
      stubEngine({ block: true, reason: "rm -rf detected", defense: "commandBlock" }),
    );
    const ev = createProbeEvent({
      source: "l1-hook",
      syscall: "tool_call",
      pid: 0,
      args: { toolName: "terminal", params: { cmd: "rm -rf /" } },
      sessionKey: "sess-1",
      runId: "run-1",
    });
    const verdict = await judge.judge(ev);
    expect(verdict).not.toBeNull();
    expect(verdict!.action).toBe("block");
    expect(verdict!.reason).toBe("rm -rf detected");
    expect(verdict!.judgeId).toBe("l1-bridge:commandBlock");
    expect(verdict!.severity).toBe("high");
  });

  it("passes params and identifiers through to the engine", async () => {
    const captured: { toolName: string; params: Record<string, unknown> }[] = [];
    const judge = createL1BridgeJudge(
      stubEngine({ block: false }, (a) => captured.push(a)),
    );
    await judge.judge(
      createProbeEvent({
        source: "l1-hook",
        syscall: "tool_call",
        pid: 0,
        args: { toolName: "write_file", params: { path: "/tmp/x", content: "y" } },
      }),
    );
    expect(captured).toHaveLength(1);
    expect(captured[0].toolName).toBe("write_file");
    expect(captured[0].params).toEqual({ path: "/tmp/x", content: "y" });
  });

  it("propagates engine throws to the aggregator", async () => {
    const judge = createL1BridgeJudge({
      checkToolCall: () => {
        throw new Error("engine boom");
      },
    });
    await expect(
      judge.judge(
        createProbeEvent({
          source: "l1-hook",
          syscall: "tool_call",
          pid: 0,
          args: { toolName: "terminal", params: {} },
        }),
      ),
    ).rejects.toThrow(/boom/);
  });
});
