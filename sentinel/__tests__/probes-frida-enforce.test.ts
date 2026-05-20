import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createNoopRuntime } from "../runtime/noop-runtime.js";
import type { AggregatedVerdict } from "../channel/event.js";
import { handleRawMessage, type EnforceContext, type FridaScript } from "../probes/frida/loader.js";
import type { ProbeDeps } from "../probes/types.js";

let baseDir: string;

beforeEach(() => {
  baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-frida-enforce-"));
});

afterEach(() => {
  fs.rmSync(baseDir, { recursive: true, force: true });
});

function makeFakeScript(): { script: FridaScript; posts: unknown[] } {
  const posts: unknown[] = [];
  return {
    script: {
      load: async () => {},
      unload: async () => {},
      post: (m: unknown) => posts.push(m),
      message: { connect: () => {} },
    },
    posts,
  };
}

function blockVerdict(reason: string): AggregatedVerdict {
  return {
    final: {
      action: "block",
      severity: "critical",
      reason,
      judgeId: "fake",
      confidence: 1,
    },
    sources: [],
  };
}

function allowVerdict(): AggregatedVerdict {
  return {
    final: {
      action: "allow",
      severity: "info",
      reason: "ok",
      judgeId: "fake",
      confidence: 1,
    },
    sources: [],
  };
}

function makeDeps(
  publishImpl: (...args: unknown[]) => Promise<AggregatedVerdict | null>,
): ProbeDeps {
  const runtime = createNoopRuntime({ stateDir: baseDir });
  return {
    runtime,
    publish: publishImpl as ProbeDeps["publish"],
  };
}

describe("Frida enforce — handleDecisionRequest via handleRawMessage", () => {
  it("posts a deny response when the judge pipeline returns block", async () => {
    const { script, posts } = makeFakeScript();
    const deps = makeDeps(async () => blockVerdict("blocked by test"));
    const enforce: EnforceContext = { script, mode: "enforce", enforceTimeoutMs: 1000 };

    handleRawMessage(
      {
        type: "send",
        payload: {
          kind: "decision_request",
          id: "req-1",
          syscall: "execve",
          pid: 100,
          argv: ["/bin/cat", "/etc/shadow"],
        },
      },
      deps,
      enforce,
    );
    await new Promise((r) => setImmediate(r));
    expect(posts).toHaveLength(1);
    expect(posts[0]).toMatchObject({
      type: "decision_response_req-1",
      decision: "deny",
      reason: "blocked by test",
    });
  });

  it("posts an allow response when no block verdict is produced", async () => {
    const { script, posts } = makeFakeScript();
    const deps = makeDeps(async () => allowVerdict());
    const enforce: EnforceContext = { script, mode: "enforce", enforceTimeoutMs: 1000 };

    handleRawMessage(
      {
        type: "send",
        payload: { kind: "decision_request", id: "req-2", syscall: "openat", pid: 200, path: "/tmp/x" },
      },
      deps,
      enforce,
    );
    await new Promise((r) => setImmediate(r));
    expect(posts).toHaveLength(1);
    expect(posts[0]).toMatchObject({ type: "decision_response_req-2", decision: "allow" });
  });

  it("fails open with a timeout response when publish hangs", async () => {
    const { script, posts } = makeFakeScript();
    const deps = makeDeps(() => new Promise(() => {})); // never resolves
    const enforce: EnforceContext = { script, mode: "enforce", enforceTimeoutMs: 5 };

    handleRawMessage(
      {
        type: "send",
        payload: { kind: "decision_request", id: "req-3", syscall: "execve", pid: 1 },
      },
      deps,
      enforce,
    );
    await new Promise((r) => setTimeout(r, 30));
    expect(posts).toHaveLength(1);
    expect(posts[0]).toMatchObject({ decision: "allow", reason: "timeout" });
  });

  it("responds exactly once even when both verdict and timer fire", async () => {
    const { script, posts } = makeFakeScript();
    let resolveVerdict: (v: AggregatedVerdict) => void;
    const verdictPromise = new Promise<AggregatedVerdict>((r) => {
      resolveVerdict = r;
    });
    const deps = makeDeps(async () => await verdictPromise);
    const enforce: EnforceContext = { script, mode: "enforce", enforceTimeoutMs: 5 };

    handleRawMessage(
      {
        type: "send",
        payload: { kind: "decision_request", id: "req-4", syscall: "execve", pid: 1 },
      },
      deps,
      enforce,
    );
    await new Promise((r) => setTimeout(r, 30));
    resolveVerdict!(blockVerdict("late deny"));
    await new Promise((r) => setTimeout(r, 30));
    expect(posts).toHaveLength(1); // only the timeout's allow, not the late deny
  });

  it("does nothing when enforce context is missing (observe-only mode)", async () => {
    const { posts } = makeFakeScript();
    const deps = makeDeps(async () => blockVerdict("never used"));
    handleRawMessage(
      {
        type: "send",
        payload: { kind: "decision_request", id: "req-5", syscall: "execve", pid: 1 },
      },
      deps,
      // intentionally omit enforce ctx
    );
    await new Promise((r) => setImmediate(r));
    expect(posts).toHaveLength(0);
  });

  it("fails open if publish throws", async () => {
    const { script, posts } = makeFakeScript();
    const deps = makeDeps(async () => {
      throw new Error("boom");
    });
    const enforce: EnforceContext = { script, mode: "enforce", enforceTimeoutMs: 1000 };
    const warn = vi.spyOn(deps.runtime.logger, "warn");
    handleRawMessage(
      { type: "send", payload: { kind: "decision_request", id: "req-6", syscall: "execve", pid: 1 } },
      deps,
      enforce,
    );
    await new Promise((r) => setImmediate(r));
    expect(posts).toHaveLength(1);
    expect(posts[0]).toMatchObject({ decision: "allow", reason: "publish-error" });
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("enforce publish threw"));
  });
});

describe("Frida enforce — decision_request parsing", () => {
  it("accepts decision_request messages via parseAgentMessage", async () => {
    // Sanity test that the parser added in M4.5 wires up.
    const { script, posts } = makeFakeScript();
    const deps = makeDeps(async () => allowVerdict());
    const enforce: EnforceContext = { script, mode: "enforce", enforceTimeoutMs: 1000 };
    handleRawMessage(
      { type: "send", payload: { kind: "decision_request", id: "abc", syscall: "execve", pid: 0 } },
      deps,
      enforce,
    );
    await new Promise((r) => setImmediate(r));
    expect(posts).toHaveLength(1);
  });
});
