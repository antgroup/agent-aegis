import fs from "node:fs";
import { EventEmitter } from "node:events";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { AggregatedVerdict } from "../channel/event.js";
import { createNoopRuntime } from "../runtime/noop-runtime.js";
import {
  type ChildProcessLike,
  createUprobeProbe,
  handleLine,
} from "../probes/uprobe/loader.js";
import { detectUprobeSupport } from "../probes/uprobe/platform.js";
import type { ProbeDeps } from "../probes/types.js";

let baseDir: string;

beforeEach(() => {
  baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-uprobe-"));
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
        return null as AggregatedVerdict | null;
      },
      onVerdict: () => () => {},
    },
    published,
  };
}

function makeFakeChild(): ChildProcessLike & {
  emitStdout(s: string): void;
  emitStderr(s: string): void;
  emitExit(code: number): void;
} {
  const stdout = new EventEmitter();
  const stderr = new EventEmitter();
  const proc = new EventEmitter() as unknown as ChildProcessLike & {
    emitStdout(s: string): void;
    emitStderr(s: string): void;
    emitExit(code: number): void;
  };
  Object.assign(proc, {
    stdout,
    stderr,
    kill: () => true,
    emitStdout: (s: string) => stdout.emit("data", Buffer.from(s)),
    emitStderr: (s: string) => stderr.emit("data", Buffer.from(s)),
    emitExit: (code: number) => (proc as unknown as EventEmitter).emit("exit", code),
  });
  return proc;
}

describe("detectUprobeSupport", () => {
  it("supports linux only", () => {
    expect(detectUprobeSupport("linux").supported).toBe(true);
    expect(detectUprobeSupport("darwin").supported).toBe(false);
    expect(detectUprobeSupport("win32").supported).toBe(false);
  });
});

describe("createUprobeProbe — degradation", () => {
  it("does nothing on non-Linux platforms", async () => {
    const probe = createUprobeProbe({
      platformOverride: { supported: false, platform: "darwin", reason: "test" },
    });
    const { deps, published } = makeDeps();
    const info = vi.spyOn(deps.runtime.logger, "info");
    await probe.start(deps);
    await probe.stop();
    expect(published).toHaveLength(0);
    expect(info).toHaveBeenCalledWith(expect.stringContaining("test"));
  });

  it("warns when libc cannot be auto-detected", async () => {
    const probe = createUprobeProbe({
      platformOverride: { supported: true, platform: "linux" },
      // no libcPath, no defaultLibc
    });
    const { deps, published } = makeDeps();
    const warn = vi.spyOn(deps.runtime.logger, "warn");
    await probe.start(deps);
    expect(published).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("libc"));
  });

  it("filters SSL_* targets when opensslPath is missing and stops if empty", async () => {
    const probe = createUprobeProbe({
      platformOverride: {
        supported: true,
        platform: "linux",
        defaultLibc: "/lib/x86_64-linux-gnu/libc.so.6",
      },
      targets: ["SSL_write"],
      spawnOverride: () => {
        throw new Error("should not spawn");
      },
    });
    const { deps, published } = makeDeps();
    const info = vi.spyOn(deps.runtime.logger, "info");
    await probe.start(deps);
    expect(published).toHaveLength(0);
    expect(info).toHaveBeenCalledWith(expect.stringContaining("SSL_write"));
    expect(info).toHaveBeenCalledWith(expect.stringContaining("no usable targets"));
  });

  it("warns when spawn throws", async () => {
    const probe = createUprobeProbe({
      platformOverride: {
        supported: true,
        platform: "linux",
        defaultLibc: "/lib/x86_64-linux-gnu/libc.so.6",
      },
      spawnOverride: () => {
        throw new Error("no python");
      },
    });
    const { deps, published } = makeDeps();
    const warn = vi.spyOn(deps.runtime.logger, "warn");
    await probe.start(deps);
    expect(published).toHaveLength(0);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("spawn failed"));
  });
});

describe("createUprobeProbe — runtime path", () => {
  it("converts a syscall JSONL line into a ProbeEvent with source=uprobe", async () => {
    const fake = makeFakeChild();
    const probe = createUprobeProbe({
      platformOverride: {
        supported: true,
        platform: "linux",
        defaultLibc: "/lib/x86_64-linux-gnu/libc.so.6",
      },
      spawnOverride: () => fake,
    });
    const { deps, published } = makeDeps();
    await probe.start(deps);
    fake.emitStdout(
      '{"kind":"ready","probes":["execve"]}\n' +
        '{"kind":"syscall","syscall":"execve","pid":1234,"ppid":1,"ts":1,"path":"/bin/ls"}\n',
    );
    await new Promise((r) => setImmediate(r));
    expect(published).toHaveLength(1);
    const ev = published[0] as Record<string, unknown>;
    expect(ev.source).toBe("uprobe");
    expect(ev.syscall).toBe("execve");
    expect(ev.pid).toBe(1234);
    expect((ev.meta as Record<string, unknown>).ppid).toBe(1);
    await probe.stop();
  });

  it("forwards stderr lines as warn", async () => {
    const fake = makeFakeChild();
    const probe = createUprobeProbe({
      platformOverride: {
        supported: true,
        platform: "linux",
        defaultLibc: "/lib/x86_64-linux-gnu/libc.so.6",
      },
      spawnOverride: () => fake,
    });
    const { deps } = makeDeps();
    const warn = vi.spyOn(deps.runtime.logger, "warn");
    await probe.start(deps);
    fake.emitStderr("traceback boom\n");
    await new Promise((r) => setImmediate(r));
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("traceback boom"));
    await probe.stop();
  });

  it("warns on unexpected runner exit", async () => {
    const fake = makeFakeChild();
    const probe = createUprobeProbe({
      platformOverride: {
        supported: true,
        platform: "linux",
        defaultLibc: "/lib/x86_64-linux-gnu/libc.so.6",
      },
      spawnOverride: () => fake,
    });
    const { deps } = makeDeps();
    const warn = vi.spyOn(deps.runtime.logger, "warn");
    await probe.start(deps);
    fake.emitExit(1);
    expect(warn).toHaveBeenCalledWith(expect.stringContaining("exited unexpectedly"));
  });
});

describe("handleLine (uprobe)", () => {
  it("ignores garbage lines without throwing", () => {
    const { deps, published } = makeDeps();
    expect(() => handleLine("not json", deps)).not.toThrow();
    expect(published).toHaveLength(0);
  });

  it("emits ssl_write preview via published event", () => {
    const { deps, published } = makeDeps();
    handleLine(
      '{"kind":"syscall","syscall":"SSL_write","pid":1,"ts":1,"preview":"GET /","extra":{"size":5}}',
      deps,
    );
    expect(published).toHaveLength(1);
    const ev = published[0] as Record<string, unknown>;
    expect(ev.syscall).toBe("SSL_write");
    expect((ev.args as Record<string, unknown>).preview).toBe("GET /");
    expect((ev.args as Record<string, unknown>).size).toBe(5);
  });
});
