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

/** Helper: flush the sentinel queue and wait for pending processing. */
async function flushAndWait(sentinel: { flush(): Promise<void> }, ms = 50): Promise<void> {
  await sentinel.flush();
  // Give microtasks a chance to settle after the sync flush.
  await new Promise((r) => setTimeout(r, ms));
}

describe("startSentinel", () => {
  it("starts with no judges and returns null verdict for published events", async () => {
    const runtime = createNoopRuntime({ stateDir });
    const sentinel = startSentinel(runtime);
    expect(sentinel.status()).toMatchObject({ judges: 0, probes: 0 });
    // Probe events go through the queue, so publish returns null.
    const result = await sentinel.publish(
      createProbeEvent({ source: "test", syscall: "x", pid: 0, args: {} }),
    );
    expect(result).toBeNull();
    await sentinel.stop();
  });

  it("runs the registered judges and persists verdicts", async () => {
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

    // Publish a probe event and flush/wait so the judge pipeline runs.
    await sentinel.publish(
      createProbeEvent({
        source: "test",
        syscall: "execve",
        pid: 999,
        args: { argv: ["/bin/cat", "/etc/shadow"] },
      }),
    );
    await flushAndWait(sentinel);

    // The verdict should now be in the JSONL log.
    const probeDir = path.join(stateDir, "probe-events");
    const files = fs.readdirSync(probeDir).filter((f) => f.endsWith(".jsonl"));
    expect(files.length).toBeGreaterThan(0);
    const contents = fs.readFileSync(path.join(probeDir, files[0]), "utf8");
    expect(contents).toContain("execve");
    expect(contents).toContain("\"kind\":\"event\"");
    expect(contents).toContain("\"kind\":\"verdict\"");
    expect(contents).toContain("demo-block");
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
    // Flush the queue and wait for async processing.
    await flushAndWait(sentinel);
    await sentinel.stop();

    const probeDir = path.join(stateDir, "probe-events");
    const files = fs.readdirSync(probeDir).filter((f) => f.endsWith(".jsonl"));
    expect(files.length).toBeGreaterThan(0);
    const contents = fs.readFileSync(path.join(probeDir, files[0]), "utf8");
    expect(contents).toContain("persist-1");
    expect(contents).toContain("\"kind\":\"event\"");
    expect(contents).toContain("\"kind\":\"verdict\"");
  });

  it("reports queue stats in status()", async () => {
    const runtime = createNoopRuntime({ stateDir });
    const sentinel = startSentinel(runtime, { eventQueue: { maxDepth: 100 } });
    const status = sentinel.status();
    expect(status.judges).toBe(0);
    expect(status.probes).toBe(0);
    expect(status.queueDepth).toBe(0);
    expect(status.dropped).toBe(0);
    expect(status.sampled).toBe(0);
    await sentinel.stop();
  });

  it("backs pressure and counts drops when queue is full", async () => {
    const runtime = createNoopRuntime({ stateDir });
    const sentinel = startSentinel(runtime, { eventQueue: { maxDepth: 5 } });
    // Publish 10 events — the queue only holds 5.
    for (let i = 0; i < 10; i++) {
      sentinel.publish(
        createProbeEvent({ source: "test", syscall: "x", pid: i, args: {} }),
      );
    }
    // Some should be enqueued, some dropped.
    const status = sentinel.status();
    expect(status.dropped).toBeGreaterThan(0);
    // Flush to clean up.
    await sentinel.flush();
    await sentinel.stop();
  });
});
