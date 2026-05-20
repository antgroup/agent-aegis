import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createHermesRuntime } from "../runtime/adapters/hermes.js";

let baseDir: string;

beforeEach(() => {
  baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-hermes-"));
});

afterEach(() => {
  fs.rmSync(baseDir, { recursive: true, force: true });
});

describe("createHermesRuntime", () => {
  it("reports hermes name and observe-only capabilities", () => {
    const { runtime } = createHermesRuntime({ stateDir: baseDir });
    expect(runtime.name).toBe("hermes");
    expect(runtime.capabilities.canBlockToolCall).toBe(false);
    expect(runtime.capabilities.canTerminateProcess).toBe(false);
  });

  it("returns the provided stateDir and config verbatim", async () => {
    const { runtime } = createHermesRuntime({
      stateDir: path.join(baseDir, "x"),
      config: { foo: "bar" },
    });
    expect(runtime.getStateDir()).toBe(path.join(baseDir, "x"));
    expect(await runtime.readConfig()).toEqual({ foo: "bar" });
  });

  it("pushContext fans out to subscribers and updates getCurrentContext", () => {
    const { runtime, pushContext } = createHermesRuntime({ stateDir: baseDir });
    const seen: Array<{ sessionKey: string; runId?: string; toolName?: string }> = [];
    runtime.onContextChange((c) =>
      seen.push({ sessionKey: c.sessionKey, runId: c.runId, toolName: c.toolName }),
    );
    pushContext({ sessionKey: "sess-1" });
    pushContext({ runId: "run-1", toolName: "terminal" });
    pushContext({ toolName: undefined });
    expect(seen).toEqual([
      { sessionKey: "sess-1", runId: undefined, toolName: undefined },
      { sessionKey: "sess-1", runId: "run-1", toolName: "terminal" },
      { sessionKey: "sess-1", runId: "run-1", toolName: undefined },
    ]);
    expect(runtime.getCurrentContext().sessionKey).toBe("sess-1");
    expect(runtime.getCurrentContext().toolName).toBeUndefined();
  });

  it("getCurrentContext returns a defensive copy", () => {
    const { runtime } = createHermesRuntime({ stateDir: baseDir });
    const c1 = runtime.getCurrentContext();
    c1.pids.push(99999);
    expect(runtime.getCurrentContext().pids).not.toContain(99999);
  });

  it("pushContext({pids}) replaces rather than appends", () => {
    const { runtime, pushContext } = createHermesRuntime({
      stateDir: baseDir,
      initialContext: { pids: [1, 2] },
    });
    pushContext({ pids: [42] });
    expect(runtime.getCurrentContext().pids).toEqual([42]);
  });

  it("signalShutdown runs onShutdown callbacks once", async () => {
    const { runtime, signalShutdown } = createHermesRuntime({ stateDir: baseDir });
    let calls = 0;
    runtime.onShutdown(async () => {
      calls++;
    });
    await signalShutdown();
    await signalShutdown();
    expect(calls).toBe(1);
  });

  it("does not throw when a subscriber misbehaves", () => {
    const { runtime, pushContext } = createHermesRuntime({ stateDir: baseDir });
    const warn = vi.spyOn(runtime.logger, "warn");
    runtime.onContextChange(() => {
      throw new Error("nope");
    });
    expect(() => pushContext({ sessionKey: "new" })).not.toThrow();
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("subscriber threw"));
  });
});
