import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createProbeEvent } from "../../channel/event.js";
import type { ProbeEventSource } from "../../channel/schema.js";
import type { Probe, ProbeDeps } from "../types.js";
import { type UprobeMessage, parseUprobeMessage } from "./messages.js";
import { detectUprobeSupport, type UprobeSupport } from "./platform.js";

const PROBE_ID = "uprobe";
const EVENT_SOURCE: ProbeEventSource = "uprobe";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RUNNER = path.join(HERE, "runner", "probe.py");

export type UprobeHookTarget =
  | "execve"
  | "openat"
  | "connect"
  | "SSL_write"
  | "SSL_read";

export interface ChildProcessLike {
  stdout: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown } | null;
  stderr: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown } | null;
  on(event: "exit" | "error", listener: (...args: unknown[]) => void): unknown;
  kill(signal?: string | number): boolean;
}

export interface UprobeProbeOptions {
  /** Python interpreter for the BCC runner. Default "python3". */
  pythonBin?: string;
  /** Override runner script path. Default: bundled probe.py. */
  runnerScript?: string;
  /**
   * Override runner with a native binary (libbpf CO-RE). When set, the loader
   * spawns this binary directly with `--mode=uprobe`; pythonBin / runnerScript
   * are ignored. Reserved for M8 — currently unused in production paths.
   */
  runnerBin?: string;
  targets?: ReadonlyArray<UprobeHookTarget>;
  /**
   * Absolute path to the libc binary uprobes should attach to. Default: the
   * first hit from a short list of common distro paths (see platform.ts).
   */
  libcPath?: string;
  /** Absolute path to libssl.so for SSL_* hooks. When unset, SSL_* targets are silently dropped. */
  opensslPath?: string;
  platformOverride?: UprobeSupport;
  spawnOverride?: (cmd: string, args: string[]) => ChildProcessLike;
}

export function createUprobeProbe(opts: UprobeProbeOptions = {}): Probe {
  const support = opts.platformOverride ?? detectUprobeSupport();
  const pythonBin = opts.pythonBin ?? "python3";
  const runnerScript = opts.runnerScript ?? DEFAULT_RUNNER;
  const runnerBin = opts.runnerBin;
  const libcPath = opts.libcPath ?? support.defaultLibc;
  const opensslPath = opts.opensslPath;
  const requestedTargets = opts.targets ?? ["execve", "openat", "connect"];

  let child: ChildProcessLike | null = null;
  let stopped = false;

  async function start(d: ProbeDeps): Promise<void> {
    const log = d.runtime.logger;
    if (!support.supported) {
      log.info(`[uprobe] probe skipped: ${support.reason ?? "unsupported"}`);
      return;
    }
    if (!libcPath) {
      log.warn(
        `[uprobe] could not auto-detect libc path; set probes.uprobe.libcPath in config`,
      );
      return;
    }
    // Drop SSL_* targets if no openssl path is configured — otherwise the
    // runner aborts with an unfriendly error.
    const targets = requestedTargets.filter((t) => {
      if ((t === "SSL_write" || t === "SSL_read") && !opensslPath) {
        log.info(`[uprobe] target ${t} skipped: opensslPath not configured`);
        return false;
      }
      return true;
    });
    if (targets.length === 0) {
      log.info(`[uprobe] no usable targets after filtering; probe disabled`);
      return;
    }

    let cmd: string;
    let args: string[];
    if (runnerBin) {
      cmd = runnerBin;
      args = ["--mode=uprobe", "--targets", targets.join(","), "--libc-path", libcPath];
      if (opensslPath) args.push("--openssl-path", opensslPath);
    } else {
      cmd = pythonBin;
      args = [runnerScript, "--targets", targets.join(","), "--libc-path", libcPath];
      if (opensslPath) args.push("--openssl-path", opensslPath);
    }
    try {
      child = opts.spawnOverride
        ? opts.spawnOverride(cmd, args)
        : (spawn(cmd, args, { stdio: ["ignore", "pipe", "pipe"] }) as unknown as ChildProcessLike);
    } catch (err) {
      log.warn(`[uprobe] spawn failed; probe disabled: ${String(err)}`);
      return;
    }

    if (!child) return;
    if (child.stdout) wireStdout(child.stdout, d);
    if (child.stderr) wireStderr(child.stderr, d);
    child.on("exit", (code) => {
      if (!stopped) {
        log.warn(`[uprobe] runner exited unexpectedly with code=${String(code)}`);
      }
      child = null;
    });
    child.on("error", (err) => {
      log.warn(`[uprobe] runner error: ${String(err)}`);
    });
    log.info(`[uprobe] runner spawned: ${cmd} ${args.join(" ")}`);
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
      if (line.trim()) deps.runtime.logger.warn(`[uprobe.runner] ${line}`);
    }
  });
}

/** Exported for tests. */
export function handleLine(line: string, deps: ProbeDeps): void {
  const msg = parseUprobeMessage(line);
  if (!msg) return;
  routeMessage(msg, deps);
}

function routeMessage(msg: UprobeMessage, deps: ProbeDeps): void {
  const log = deps.runtime.logger;
  switch (msg.kind) {
    case "ready":
      log.info(`[uprobe.runner] ready; probes=${msg.probes.join(",")}`);
      return;
    case "log":
      log[msg.level](`[uprobe.runner] ${msg.message}`);
      return;
    case "syscall": {
      const ctx = deps.runtime.getCurrentContext();
      const event = createProbeEvent({
        source: EVENT_SOURCE,
        syscall: msg.syscall,
        pid: msg.pid,
        timestamp: msg.ts,
        args: buildArgs(msg),
        sessionKey: ctx.sessionKey,
        runId: ctx.runId,
        toolName: ctx.toolName,
        meta:
          msg.ppid !== undefined
            ? { ppid: msg.ppid, comm: msg.comm }
            : { comm: msg.comm },
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
  preview?: string;
  extra?: Record<string, unknown>;
}): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  if (msg.argv) out.argv = msg.argv;
  if (msg.path) out.path = msg.path;
  if (msg.addr) out.addr = msg.addr;
  if (msg.preview) out.preview = msg.preview;
  if (msg.extra) Object.assign(out, msg.extra);
  return out;
}
