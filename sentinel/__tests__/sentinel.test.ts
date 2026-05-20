import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createProbeEvent } from "../channel/event.js";
import { createNoopRuntime } from "../runtime/noop-runtime.js";
import type { Judge } from "../judges/base.js";
import { startSentinel } from "../index.js";

let stateDir: string;

beforeEach(() => {
  stateDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-it-"));
});

afterEach(() => {
  fs.rmSync(stateDir, { recursive: true, force: true });
});

describe("startSentinel", () => {
  it("starts with no judges and returns null verdict for published events", async () => {
    const runtime = createNoopRuntime({ stateDir });
    const sentinel = startSentinel(runtime);
    expect(sentinel.status()).toEqual({ judges: 0, probes: 0 });
    const result = await sentinel.publish(
      createProbeEvent({ source: "test", syscall: "x", pid: 0, args: {} }),
    );
    expect(result).toBeNull();
    await sentinel.stop();
  });

  it("runs the registered judges and aggregates verdicts", async () => {
    const runtime = createNoopRuntime({ stateDir });
    const sentinel = startSentinel(runtime);
    const blockJudge: Judge = {
      id: "demo-block",
      judge: async () => ({
        action: "block",
        severity: "high",
        reason: "demo block",
        judgeId: "demo-block",
        confidence: 1,
      }),
    };
    const observeJudge: Judge = {
      id: "demo-observe",
      judge: async () => ({
        action: "observe",
        severity: "low",
        reason: "demo observe",
        judgeId: "demo-observe",
        confidence: 1,
      }),
    };
    sentinel.registerJudge(blockJudge);
    sentinel.registerJudge(observeJudge);
    expect(sentinel.status().judges).toBe(2);

    const result = await sentinel.publish(
      createProbeEvent({
        source: "test",
        syscall: "execve",
        pid: 999,
        args: { argv: ["/bin/cat", "/etc/shadow"] },
      }),
    );
    expect(result).not.toBeNull();
    expect(result!.final.action).toBe("block");
    expect(result!.sources).toHaveLength(2);
    await sentinel.stop();
  });

  it("persists events and verdicts to JSONL", async () => {
    const runtime = createNoopRuntime({ stateDir });
    const sentinel = startSentinel(runtime);
    sentinel.registerJudge({
      id: "persist-test",
      judge: async () => ({
        action: "observe",
        severity: "info",
        reason: "log",
        judgeId: "persist-test",
        confidence: 1,
      }),
    });
    await sentinel.publish(
      createProbeEvent({ source: "test", syscall: "openat", pid: 1, args: {}, id: "persist-1" }),
    );
    await sentinel.stop();

    const probeDir = path.join(stateDir, "probe-events");
    const files = fs.readdirSync(probeDir).filter((f) => f.endsWith(".jsonl"));
    expect(files.length).toBeGreaterThan(0);
    const contents = fs.readFileSync(path.join(probeDir, files[0]), "utf8");
    expect(contents).toContain("persist-1");
    expect(contents).toContain("\"kind\":\"event\"");
    expect(contents).toContain("\"kind\":\"verdict\"");
  });
});
