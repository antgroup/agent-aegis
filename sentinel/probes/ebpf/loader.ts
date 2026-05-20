import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createProbeEvent } from "../../channel/event.js";
import type { ProbeEventSource } from "../../channel/schema.js";
import type { Probe, ProbeDeps } from "../types.js";
import { type EbpfMessage, parseEbpfMessage } from "./messages.js";
import { detectEbpfSupport, type EbpfSupport } from "./platform.js";

const PROBE_ID = "ebpf";
const EVENT_SOURCE: ProbeEventSource = "ebpf";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RUNNER = path.join(HERE, "runner", "probe.py");

/**
 * Minimal subset of `ChildProcess` the loader uses. Lets tests inject a fake
 * without needing the full Node child_process surface.
 */
export interface ChildProcessLike {
  stdout: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown } | null;
  stderr: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown } | null;
  on(event: "exit" | "error", listener: (...args: unknown[]) => void): unknown;
  kill(signal?: string | number): boolean;
}

export interface EbpfProbeOptions {
  pythonBin?: string;
  runnerScript?: string;
  targets?: ReadonlyArray<"execve" | "openat" | "connect">;
  /** Test seam: override platform detection. */
  platformOverride?: EbpfSupport;
  /** Test seam: override spawn so we don't actually launch python. */
  spawnOverride?: (cmd: string, args: string[]) => ChildProcessLike;
}

export function createEbpfProbe(opts: EbpfProbeOptions = {}): Probe {
  const support = opts.platformOverride ?? detectEbpfSupport();
  const pythonBin = opts.pythonBin ?? "python3";
  const runnerScript = opts.runnerScript ?? DEFAULT_RUNNER;
  const targets = opts.targets ?? ["execve", "openat", "connect"];

  let child: ChildProcessLike | null = null;
  let stopped = false;

  async function start(d: ProbeDeps): Promise<void> {
    const log = d.runtime.logger;
    if (!support.supported) {
      log.info(`[ebpf] probe skipped: ${support.reason ?? "unsupported"}`);
      return;
    }

    const args = [runnerScript, "--targets", targets.join(",")];
    try {
      child = opts.spawnOverride
        ? opts.spawnOverride(pythonBin, args)
        : (spawn(pythonBin, args, { stdio: ["ignore", "pipe", "pipe"] }) as unknown as ChildProcessLike);
    } catch (err) {
      log.warn(`[ebpf] spawn failed; probe disabled: ${String(err)}`);
      return;
    }

    if (!child) return;
    if (child.stdout) wireStdout(child.stdout, d);
    if (child.stderr) wireStderr(child.stderr, d);
    child.on("exit", (code) => {
      if (!stopped) {
        log.warn(`[ebpf] runner exited unexpectedly with code=${String(code)}`);
      }
      child = null;
    });
    child.on("error", (err) => {
      log.warn(`[ebpf] runner error: ${String(err)}`);
    });
    log.info(`[ebpf] runner spawned: ${pythonBin} ${args.join(" ")}`);
  }

  async function stop(): Promise<void> {
    stopped = true;
    if (child) {
      try {
        child.kill("SIGTERM");
      } catch {
        // ignore
      }
      child = null;
    }
  }

  return { id: PROBE_ID, start, stop };
}

function wireStdout(
  stdout: NonNullable<ChildProcessLike["stdout"]>,
  deps: ProbeDeps,
): void {
  let buf = "";
  stdout.on("data", (chunk) => {
    buf += typeof chunk === "string" ? chunk : chunk.toString("utf8");
    let idx = buf.indexOf("\n");
    while (idx !== -1) {
      const line = buf.slice(0, idx);
      buf = buf.slice(idx + 1);
      handleLine(line, deps);
      idx = buf.indexOf("\n");
    }
  });
}

function wireStderr(
  stderr: NonNullable<ChildProcessLike["stderr"]>,
  deps: ProbeDeps,
): void {
  stderr.on("data", (chunk) => {
    const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
    for (const line of text.split("\n")) {
      if (line.trim()) deps.runtime.logger.warn(`[ebpf.runner] ${line}`);
    }
  });
}

/** Exported for tests. */
export function handleLine(line: string, deps: ProbeDeps): void {
  const msg = parseEbpfMessage(line);
  if (!msg) return;
  routeMessage(msg, deps);
}

function routeMessage(msg: EbpfMessage, deps: ProbeDeps): void {
  const log = deps.runtime.logger;
  switch (msg.kind) {
    case "ready":
      log.info(`[ebpf.runner] ready; probes=${msg.probes.join(",")}`);
      return;
    case "log":
      log[msg.level](`[ebpf.runner] ${msg.message}`);
      return;
    case "syscall": {
      const event = createProbeEvent({
        source: EVENT_SOURCE,
        syscall: msg.syscall,
        pid: msg.pid,
        timestamp: msg.ts,
        args: buildArgs(msg),
        sessionKey: deps.runtime.getCurrentContext().sessionKey,
        runId: deps.runtime.getCurrentContext().runId,
        toolName: deps.runtime.getCurrentContext().toolName,
        meta: msg.ppid !== undefined ? { ppid: msg.ppid, comm: msg.comm } : { comm: msg.comm },
      });
      void deps.publish(event);
      return;
    }
  }
}

function buildArgs(msg: {
  argv?: string[];
  path?: string;
  addr?: string;
  extra?: Record<string, unknown>;
}): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (msg.argv) out.argv = msg.argv;
  if (msg.path) out.path = msg.path;
  if (msg.addr) out.addr = msg.addr;
  if (msg.extra) Object.assign(out, msg.extra);
  return out;
}
