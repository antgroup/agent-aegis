import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createProbeEvent } from "../channel/event.js";
import { createNoopRuntime } from "../runtime/noop-runtime.js";
import { detectFridaSupport } from "../probes/frida/platform.js";
import { createFridaProbe, handleRawMessage, type FridaModuleLike } from "../probes/frida/loader.js";
import type { ProbeDeps } from "../probes/types.js";
import { startSentinel } from "../index.js";

let baseDir: string;

beforeEach(() => {
  baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-frida-"));
});

afterEach(() => {
  fs.rmSync(baseDir, { recursive: true, force: true });
});

function makeDeps(): { deps: ProbeDeps; published: unknown[] } {
  const runtime = createNoopRuntime({ stateDir: baseDir });
  const published: unknown[] = [];
  return {
    deps: {
      runtime,
      publish: async (e) => {
        published.push(e);
      },
    },
    published,
  };
}

describe("detectFridaSupport", () => {
  it("supports linux and darwin", () => {
    expect(detectFridaSupport("linux").supported).toBe(true);
    expect(detectFridaSupport("darwin").supported).toBe(true);
  });

  it("marks win32 as unsupported with a reason", () => {
    const s = detectFridaSupport("win32");
    expect(s.supported).toBe(false);
    expect(s.reason).toBeTruthy();
    expect(s.agentScriptPath).toMatch(/agent-win\.js$/);
  });
});

describe("createFridaProbe — degradation", () => {
  it("does nothing on unsupported platforms", async () => {
    const probe = createFridaProbe({
      platformOverride: {
        supported: false,
        platform: "win32",
        agentScriptPath: "/tmp/x",
        defaultTargets: [],
        reason: "test override",
      },
    });
    const { deps, published } = makeDeps();
    const warn = vi.spyOn(deps.runtime.logger, "info");
    await probe.start(deps);
    await probe.stop();
    expect(published).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("test override"));
  });

  it("warns and disables when frida module is null", async () => {
    const probe = createFridaProbe({
      fridaModuleOverride: null,
      platformOverride: {
        supported: true,
        platform: "linux",
        agentScriptPath: "/dev/null",
        defaultTargets: ["execve"],
      },
      agentScriptOverride: "// stub",
    });
    const { deps, published } = makeDeps();
    const warn = vi.spyOn(deps.runtime.logger, "warn");
    await probe.start(deps);
    expect(published).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("not installed"));
  });

  it("attaches to the requested pid and posts a configure message", async () => {
    const postCalls: unknown[] = [];
    const fakeScript = {
      load: vi.fn().mockResolvedValue(undefined),
      unload: vi.fn().mockResolvedValue(undefined),
      post: (m: unknown) => postCalls.push(m),
      message: { connect: vi.fn() },
    };
    const fakeSession = {
      createScript: vi.fn().mockResolvedValue(fakeScript),
      detach: vi.fn().mockResolvedValue(undefined),
    };
    const fakeFrida: FridaModuleLike = {
      attach: vi.fn().mockResolvedValue(fakeSession),
    };

    const probe = createFridaProbe({
      fridaModuleOverride: fakeFrida,
      platformOverride: {
        supported: true,
        platform: "linux",
        agentScriptPath: "/dev/null",
        defaultTargets: ["execve", "openat", "connect"],
      },
      agentScriptOverride: "// fake agent",
      attachPid: 9999,
    });
    const { deps } = makeDeps();
    await probe.start(deps);

    expect(fakeFrida.attach).toHaveBeenCalledWith(9999);
    expect(fakeSession.createScript).toHaveBeenCalledWith("// fake agent");
    expect(fakeScript.load).toHaveBeenCalled();
    expect(postCalls).toHaveLength(1);
    expect(postCalls[0]).toMatchObject({
      type: "configure",
      targets: ["execve", "openat", "connect"],
    });

    await probe.stop();
    expect(fakeScript.unload).toHaveBeenCalled();
    expect(fakeSession.detach).toHaveBeenCalled();
  });
});

describe("handleRawMessage", () => {
  it("publishes a ProbeEvent for syscall messages and unwraps frida envelopes", async () => {
    const { deps, published } = makeDeps();
    handleRawMessage(
      {
        type: "send",
        payload: {
          kind: "syscall",
          syscall: "execve",
          pid: 1234,
          ts: 5,
          argv: ["/bin/cat", "/etc/shadow"],
        },
      },
      deps,
    );
    // publish is async (Promise<void>); allow the next microtask.
    await new Promise((r) => setImmediate(r));
    expect(published).toHaveLength(1);
    const ev = published[0] as ReturnType<typeof createProbeEvent>;
    expect(ev.source).toBe("frida");
    expect(ev.syscall).toBe("execve");
    expect(ev.pid).toBe(1234);
    expect(ev.args.argv).toEqual(["/bin/cat", "/etc/shadow"]);
  });

  it("routes log messages to runtime logger", () => {
    const { deps } = makeDeps();
    const info = vi.spyOn(deps.runtime.logger, "info");
    handleRawMessage(
      { type: "send", payload: { kind: "log", level: "info", message: "hello" } },
      deps,
    );
    expect(info).toHaveBeenCalledWith(expect.stringContaining("hello"));
  });

  it("logs ready messages", () => {
    const { deps } = makeDeps();
    const info = vi.spyOn(deps.runtime.logger, "info");
    handleRawMessage(
      { type: "send", payload: { kind: "ready", hookedTargets: ["execve"] } },
      deps,
    );
    expect(info).toHaveBeenCalledWith(expect.stringContaining("execve"));
  });

  it("ignores malformed messages without throwing", () => {
    const { deps, published } = makeDeps();
    expect(() => handleRawMessage({ type: "send", payload: { kind: "bogus" } }, deps)).not.toThrow();
    expect(published).toHaveLength(0);
  });
});

describe("sentinel.registerProbe integration", () => {
  it("counts a successfully started probe and runs stop on shutdown", async () => {
    const runtime = createNoopRuntime({ stateDir: baseDir });
    const sentinel = startSentinel(runtime);
    let started = 0;
    let stopped = 0;
    await sentinel.registerProbe({
      id: "test-probe",
      async start() {
        started++;
      },
      async stop() {
        stopped++;
      },
    });
    expect(sentinel.status()).toEqual({ judges: 0, probes: 1 });
    expect(started).toBe(1);
    await sentinel.stop();
    expect(stopped).toBe(1);
  });

  it("does not count a probe whose start throws", async () => {
    const runtime = createNoopRuntime({ stateDir: baseDir });
    const sentinel = startSentinel(runtime);
    await sentinel.registerProbe({
      id: "bad-probe",
      async start() {
        throw new Error("nope");
      },
      async stop() {
        /* unreachable */
      },
    });
    expect(sentinel.status()).toEqual({ judges: 0, probes: 0 });
    await sentinel.stop();
  });
});
