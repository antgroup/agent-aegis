import fs from "node:fs";
import { EventEmitter } from "node:events";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AggregatedVerdict, Verdict } from "../channel/event.js";
import { createNoopRuntime } from "../runtime/noop-runtime.js";
import {
  type ChildProcessLike,
  createLsmProbe,
  handleLine,
} from "../probes/lsm/loader.js";
import type { ProbeDeps } from "../probes/types.js";

let baseDir: string;

beforeEach(() => {
  baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-lsm-"));
});

afterEach(() => {
  fs.rmSync(baseDir, { recursive: true, force: true });
});

interface DepsBundle {
  deps: ProbeDeps;
  published: unknown[];
  emitVerdict: (v: AggregatedVerdict) => void;
}

function makeDeps(): DepsBundle {
  const runtime = createNoopRuntime({ stateDir: baseDir });
  const published: unknown[] = [];
  const subscribers = new Set<(v: AggregatedVerdict) => void>();
  return {
    deps: {
      runtime,
      publish: async (e) => {
        published.push(e);
        return null as AggregatedVerdict | null;
      },
      onVerdict: (cb) => {
        subscribers.add(cb);
        return () => {
          subscribers.delete(cb);
        };
      },
    },
    published,
    emitVerdict: (v) => {
      for (const s of subscribers) s(v);
    },
  };
}

interface FakeChild extends ChildProcessLike {
  emitStdout(s: string): void;
  emitStderr(s: string): void;
  emitExit(code: number): void;
  written: string[];
}

function makeFakeChild(): FakeChild {
  const stdout = new EventEmitter();
  const stderr = new EventEmitter();
  const written: string[] = [];
  const proc = new EventEmitter() as unknown as FakeChild;
  Object.assign(proc, {
    stdin: {
      write(chunk: string | Buffer) {
        written.push(typeof chunk === "string" ? chunk : chunk.toString());
        return true;
      },
    },
    stdout,
    stderr,
    kill: () => true,
    written,
    emitStdout: (s: string) => stdout.emit("data", Buffer.from(s)),
    emitStderr: (s: string) => stderr.emit("data", Buffer.from(s)),
    emitExit: (code: number) => (proc as unknown as EventEmitter).emit("exit", code),
  });
  return proc;
}

function mkBlockVerdict(reason: string, severity: Verdict["severity"] = "critical"): AggregatedVerdict {
  const final: Verdict = {
    action: "block",
    severity,
    reason,
    judgeId: "native:sensitive-path",
    confidence: 1,
  };
  return { final, sources: [final] };
}

describe("createLsmProbe — degradation", () => {
  it("does nothing on non-Linux platforms", async () => {
    const probe = createLsmProbe({
      platformOverride: { supported: false, platform: "darwin", reason: "test" },
    });
    const { deps, published } = makeDeps();
    const info = vi.spyOn(deps.runtime.logger, "info");
    await probe.start(deps);
    await probe.stop();
    expect(published).toHaveLength(0);
    expect(info).toHaveBeenCalledWith(expect.stringContaining("test"));
  });

  it("warns when spawn throws", async () => {
    const probe = createLsmProbe({
      platformOverride: { supported: true, platform: "linux" },
      spawnOverride: () => {
        throw new Error("no binary");
      },
    });
    const { deps } = makeDeps();
    const warn = vi.spyOn(deps.runtime.logger, "warn");
    await probe.start(deps);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("spawn failed"));
  });
});

describe("createLsmProbe — verdict → policy", () => {
  it("writes policy_upsert to runner stdin on qualifying verdict", async () => {
    const fake = makeFakeChild();
    const probe = createLsmProbe({
      platformOverride: { supported: true, platform: "linux" },
      spawnOverride: () => fake,
    });
    const bundle = makeDeps();
    await probe.start(bundle.deps);

    bundle.emitVerdict(
      mkBlockVerdict("native: sensitive path access blocked (x); path=/etc/shadow"),
    );

    expect(fake.written).toHaveLength(1);
    const sent = JSON.parse(fake.written[0].trim());
    expect(sent.kind).toBe("policy_upsert");
    expect(sent.entry.kind).toBe("open_path");
    expect(sent.entry.value).toBe("/etc/shadow");
    expect(probe.policySize()).toBe(1);
  });

  it("ignores verdicts below minSeverity", async () => {
    const fake = makeFakeChild();
    const probe = createLsmProbe({
      platformOverride: { supported: true, platform: "linux" },
      spawnOverride: () => fake,
      minSeverity: "critical",
    });
    const bundle = makeDeps();
    await probe.start(bundle.deps);

    bundle.emitVerdict(
      mkBlockVerdict("native: sensitive path access blocked (x); path=/etc/shadow", "high"),
    );
    expect(fake.written).toHaveLength(0);
    expect(probe.policySize()).toBe(0);
  });

  it("clearPolicy sends policy_clear and resets size", async () => {
    const fake = makeFakeChild();
    const probe = createLsmProbe({
      platformOverride: { supported: true, platform: "linux" },
      spawnOverride: () => fake,
    });
    const bundle = makeDeps();
    await probe.start(bundle.deps);

    bundle.emitVerdict(
      mkBlockVerdict("native: sensitive path access blocked (x); path=/etc/shadow"),
    );
    expect(probe.policySize()).toBe(1);

    probe.clearPolicy();
    expect(probe.policySize()).toBe(0);
    const last = fake.written.at(-1);
    expect(last).toBeDefined();
    expect(JSON.parse(last!.trim())).toEqual({ kind: "policy_clear" });
  });
});

describe("handleLine (LSM)", () => {
  it("publishes deny events as source=lsm ProbeEvents", () => {
    const { deps, published } = makeDeps();
    handleLine(
      '{"kind":"deny","hook":"file_open","pid":42,"ppid":1,"comm":"cat","match":"/etc/shadow","ts":1}',
      deps,
    );
    expect(published).toHaveLength(1);
    const ev = published[0] as Record<string, unknown>;
    expect(ev.source).toBe("lsm");
    expect(ev.syscall).toBe("openat");
    expect(ev.pid).toBe(42);
    const args = ev.args as Record<string, unknown>;
    expect(args.denied).toBe(true);
    expect(args.path).toBe("/etc/shadow");
  });

  it("maps bprm_check_security to execve", () => {
    const { deps, published } = makeDeps();
    handleLine(
      '{"kind":"deny","hook":"bprm_check_security","pid":42,"match":"/tmp/x","ts":1}',
      deps,
    );
    const ev = published[0] as Record<string, unknown>;
    expect(ev.syscall).toBe("execve");
  });

  it("ignores garbage without throwing", () => {
    const { deps, published } = makeDeps();
    expect(() => handleLine("not json", deps)).not.toThrow();
    expect(published).toHaveLength(0);
  });
});
