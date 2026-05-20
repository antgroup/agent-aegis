import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { OpenClawPluginApi } from "../../runtime-api.js";
import { createOpenClawRuntime } from "../runtime/adapters/openclaw.js";

interface FakeApi extends OpenClawPluginApi {
  readonly logs: { level: string; msg: string }[];
  readonly registeredHooks: Map<string, Array<(event: unknown, ctx: unknown) => unknown>>;
  fire(hook: string, event: unknown, ctx: unknown): void;
}

function createFakeApi(opts: {
  stateDir: string;
  pluginConfig?: Record<string, unknown>;
  getterConfig?: Record<string, unknown>;
}): FakeApi {
  const logs: FakeApi["logs"] = [];
  const log = (level: string) => (msg: string) => {
    logs.push({ level, msg });
  };
  const registeredHooks: FakeApi["registeredHooks"] = new Map();
  return {
    logs,
    registeredHooks,
    fire(hook, event, ctx) {
      const handlers = registeredHooks.get(hook) ?? [];
      for (const h of handlers) h(event, ctx);
    },
    logger: {
      info: log("info"),
      warn: log("warn"),
      error: log("error"),
    },
    runtime: {
      state: { resolveStateDir: () => opts.stateDir },
    },
    on: (hook, handler) => {
      const list = registeredHooks.get(hook) ?? [];
      list.push(handler);
      registeredHooks.set(hook, list);
    },
    pluginConfig: opts.pluginConfig,
    getPluginConfig: (id) => (id === "claw-aegis" ? opts.getterConfig : undefined),
    resolvePath: (p) => p,
  };
}

let baseDir: string;

beforeEach(() => {
  baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-openclaw-"));
});

afterEach(() => {
  fs.rmSync(baseDir, { recursive: true, force: true });
});

describe("createOpenClawRuntime", () => {
  it("reports openclaw name and reasonable capabilities", () => {
    const api = createFakeApi({ stateDir: baseDir });
    const rt = createOpenClawRuntime(api);
    expect(rt.name).toBe("openclaw");
    expect(rt.capabilities.canBlockToolCall).toBe(false);
    expect(rt.capabilities.canTerminateProcess).toBe(false);
    expect(["linux", "darwin", "win32", "unknown"]).toContain(rt.capabilities.platform);
  });

  it("namespaces state directory under sentinel/ by default", () => {
    const api = createFakeApi({ stateDir: baseDir });
    const rt = createOpenClawRuntime(api);
    expect(rt.getStateDir()).toBe(path.join(baseDir, "sentinel"));
  });

  it("honors a custom stateSubdir", () => {
    const api = createFakeApi({ stateDir: baseDir });
    const rt = createOpenClawRuntime(api, { stateSubdir: "probes-only" });
    expect(rt.getStateDir()).toBe(path.join(baseDir, "probes-only"));
  });

  it("folds multi-arg AgentLogger calls into single-arg openclaw logger", () => {
    const api = createFakeApi({ stateDir: baseDir });
    const rt = createOpenClawRuntime(api);
    rt.logger.info("hello", { a: 1 }, "world");
    rt.logger.error("boom");
    expect(api.logs).toEqual([
      { level: "info", msg: 'hello {"a":1} world' },
      { level: "error", msg: "boom" },
    ]);
  });

  it("falls back to info when openclaw logger has no debug", () => {
    const api = createFakeApi({ stateDir: baseDir });
    const rt = createOpenClawRuntime(api);
    rt.logger.debug("dbg-msg");
    expect(api.logs).toEqual([{ level: "info", msg: "dbg-msg" }]);
  });

  it("reads from api.pluginConfig and merges with manifest userConfig as low-priority defaults", async () => {
    // Observed behavior in OpenClaw 2026.5.7: api.pluginConfig only carries
    // schema fields with primitive defaults — nested objects (like our
    // probes block) get dropped. The adapter augments pluginConfig with the
    // plugin manifest's userConfig block for those gaps. Precedence:
    // pluginConfig wins where present; manifest fills the rest.
    const manifestRoot = fs.mkdtempSync(path.join(baseDir, "plug-"));
    fs.writeFileSync(
      path.join(manifestRoot, "openclaw.plugin.json"),
      JSON.stringify({ userConfig: { fromManifest: 1, shared: "manifest" } }),
    );

    const apiBoth = createFakeApi({
      stateDir: baseDir,
      pluginConfig: { fromPluginConfig: 2, shared: "pluginConfig" },
    });
    (apiBoth as { rootDir?: string }).rootDir = manifestRoot;
    const merged = await createOpenClawRuntime(apiBoth).readConfig();
    expect(merged).toEqual({
      fromPluginConfig: 2,
      shared: "pluginConfig", // pluginConfig wins
      fromManifest: 1,         // present only in manifest
    });

    const apiManifestOnly = createFakeApi({ stateDir: baseDir });
    (apiManifestOnly as { rootDir?: string }).rootDir = manifestRoot;
    expect(await createOpenClawRuntime(apiManifestOnly).readConfig()).toEqual({
      fromManifest: 1,
      shared: "manifest",
    });

    const apiEmpty = createFakeApi({ stateDir: baseDir });
    expect(await createOpenClawRuntime(apiEmpty).readConfig()).toEqual({});
  });

  it("updates context from hook events and notifies subscribers", () => {
    const api = createFakeApi({ stateDir: baseDir });
    const rt = createOpenClawRuntime(api);
    const seen: Array<{ sessionKey: string; runId?: string; toolName?: string }> = [];
    rt.onContextChange((c) =>
      seen.push({ sessionKey: c.sessionKey, runId: c.runId, toolName: c.toolName }),
    );

    api.fire("message_received", { content: "hi" }, { sessionKey: "sess-1" });
    api.fire("before_tool_call", { toolName: "terminal" }, { sessionKey: "sess-1", runId: "run-1" });
    api.fire("after_tool_call", { toolName: "terminal" }, { sessionKey: "sess-1", runId: "run-1" });
    api.fire("session_end", {}, { sessionKey: "sess-1" });

    expect(seen).toEqual([
      { sessionKey: "sess-1", runId: undefined, toolName: undefined },
      { sessionKey: "sess-1", runId: "run-1", toolName: "terminal" },
      { sessionKey: "sess-1", runId: "run-1", toolName: undefined },
      { sessionKey: "default", runId: undefined, toolName: undefined },
    ]);
  });

  it("getCurrentContext returns a defensive copy", () => {
    const api = createFakeApi({ stateDir: baseDir });
    const rt = createOpenClawRuntime(api);
    const snapshot = rt.getCurrentContext();
    snapshot.sessionKey = "mutated";
    snapshot.pids.push(99999);
    expect(rt.getCurrentContext().sessionKey).toBe("default");
    expect(rt.getCurrentContext().pids).not.toContain(99999);
  });

  it("registerToolCallInterceptor stores the handler but never calls it in M3", () => {
    const api = createFakeApi({ stateDir: baseDir });
    const rt = createOpenClawRuntime(api);
    let called = 0;
    rt.registerToolCallInterceptor(async () => {
      called++;
      return {
        block: false,
        aggregated: { final: { action: "allow", severity: "info", reason: "x", judgeId: "y", confidence: 1 }, sources: [] },
      };
    });
    api.fire("before_tool_call", { toolName: "terminal" }, { runId: "r" });
    // Even after a tool-call hook fires, the interceptor must not run; L1
    // hooks own the tool-call decision path in M3.
    expect(called).toBe(0);
  });
});
