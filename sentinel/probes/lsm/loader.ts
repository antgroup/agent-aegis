import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createProbeEvent } from "../../channel/event.js";
import type { ProbeEventSource, VerdictSeverity } from "../../channel/schema.js";
import type { Probe, ProbeDeps } from "../types.js";
import { type LsmRunnerMessage, parseLsmRunnerMessage } from "./messages.js";
import { detectLsmSupport, type LsmSupport } from "./platform.js";
import { encodePolicyMessage, PolicyTable } from "./policy.js";

const PROBE_ID = "lsm";
const EVENT_SOURCE: ProbeEventSource = "lsm";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RUNNER_BIN = path.join(HERE, "runner", "dist", "lsm-runner");

export type LsmMinSeverity = Extract<VerdictSeverity, "high" | "critical">;

export interface ChildProcessLike {
  stdin: { write(chunk: string | Buffer): boolean; end?(): void } | null;
  stdout: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown } | null;
  stderr: { on(event: "data", listener: (chunk: Buffer | string) => void): unknown } | null;
  on(event: "exit" | "error", listener: (...args: unknown[]) => void): unknown;
  kill(signal?: string | number): boolean;
}

export interface LsmProbeOptions {
  /** Override path to the compiled Go runner binary. */
  runnerBin?: string;
  /** Policy entry TTL (seconds). Default 3600. */
  policyTtlSeconds?: number;
  /** Maximum number of policy entries kept in memory + pushed to BPF map. Default 1024. */
  maxEntries?: number;
  /** Minimum severity that produces a policy entry. Default "high". */
  minSeverity?: LsmMinSeverity;
  /** Unused in stdio mode; reserved for future unix-socket transport. */
  socketPath?: string;
  /** Probe-specific state directory; not currently consumed by the runner. */
  stateDir?: string;
  platformOverride?: LsmSupport;
  spawnOverride?: (cmd: string, args: string[]) => ChildProcessLike;
  /** Test seam — defaults to Date.now. */
  now?: () => number;
}

export interface LsmProbeHandle extends Probe {
  /** Diagnostic — current policy entry count. */
  policySize(): number;
  /** Clear all policy entries (also sent to runner). */
  clearPolicy(): void;
}

export function createLsmProbe(opts: LsmProbeOptions = {}): LsmProbeHandle {
  const support = opts.platformOverride ?? detectLsmSupport();
  const runnerBin = opts.runnerBin ?? DEFAULT_RUNNER_BIN;
  const ttlMs = (opts.policyTtlSeconds ?? 3600) * 1000;
  const maxEntries = opts.maxEntries ?? 1024;
  const minSeverity: LsmMinSeverity = opts.minSeverity ?? "high";
  const now = opts.now ?? Date.now;
  const policy = new PolicyTable({ ttlMs, maxEntries, minSeverity, now });

  let child: ChildProcessLike | null = null;
  let stopped = false;
  let unsubscribeVerdicts: (() => void) | null = null;

  async function start(d: ProbeDeps): Promise<void> {
    const log = d.runtime.logger;
    if (!support.supported) {
      log.info(`[lsm] probe skipped: ${support.reason ?? "unsupported"}`);
      return;
    }

    const args = ["--mode=lsm"];
    try {
      child = opts.spawnOverride
        ? opts.spawnOverride(runnerBin, args)
        : (spawn(runnerBin, args, {
            stdio: ["pipe", "pipe", "pipe"],
          }) as unknown as ChildProcessLike);
    } catch (err) {
      log.warn(`[lsm] spawn failed; probe disabled: ${String(err)}`);
      return;
    }
    if (!child) return;

    if (child.stdout) wireStdout(child.stdout, d);
    if (child.stderr) wireStderr(child.stderr, d);
    child.on("exit", (code) => {
      if (!stopped) {
        log.warn(`[lsm] runner exited unexpectedly with code=${String(code)}`);
      }
      child = null;
    });
    child.on("error", (err) => {
      log.warn(`[lsm] runner error: ${String(err)}`);
    });
    log.info(`[lsm] runner spawned: ${runnerBin} ${args.join(" ")}`);

    // Subscribe to every verdict the sentinel emits; high-severity blocks
    // become policy entries. The runner reads policy updates from stdin and
    // mirrors them into the BPF policy_map.
    unsubscribeVerdicts = d.onVerdict((v) => {
      const entry = policy.ingest(v);
      if (!entry) return;
      const c = child;
      if (!c || !c.stdin) return;
      try {
        c.stdin.write(encodePolicyMessage({ kind: "policy_upsert", entry }));
      } catch (err) {
        log.warn(`[lsm] policy_upsert write failed: ${String(err)}`);
      }
    });
  }

  async function stop(): Promise<void> {
    stopped = true;
    if (unsubscribeVerdicts) {
      unsubscribeVerdicts();
      unsubscribeVerdicts = null;
    }
    if (child) {
      try {
        child.kill("SIGTERM");
      } catch {
        // ignore
      }
      child = null;
    }
  }

  function policySize(): number {
    return policy.size();
  }

  function clearPolicy(): void {
    policy.clear();
    if (child && child.stdin) {
      try {
        child.stdin.write(encodePolicyMessage({ kind: "policy_clear" }));
      } catch {
        // ignore — best-effort sync
      }
    }
  }

  return { id: PROBE_ID, start, stop, policySize, clearPolicy };
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
      if (line.trim()) deps.runtime.logger.warn(`[lsm.runner] ${line}`);
    }
  });
}

/** Exported for tests. */
export function handleLine(line: string, deps: ProbeDeps): void {
  const msg = parseLsmRunnerMessage(line);
  if (!msg) return;
  routeMessage(msg, deps);
}

function routeMessage(msg: LsmRunnerMessage, deps: ProbeDeps): void {
  const log = deps.runtime.logger;
  switch (msg.kind) {
    case "ready":
      log.info(`[lsm.runner] ready; hooks=${msg.hooks.join(",")}`);
      return;
    case "log":
      log[msg.level](`[lsm.runner] ${msg.message}`);
      return;
    case "deny": {
      const ctx = deps.runtime.getCurrentContext();
      const event = createProbeEvent({
        source: EVENT_SOURCE,
        syscall: hookToSyscall(msg.hook),
        pid: msg.pid,
        timestamp: msg.ts,
        args: { path: msg.match, denied: true, hook: msg.hook },
        sessionKey: ctx.sessionKey,
        runId: ctx.runId,
        toolName: ctx.toolName,
        meta:
          msg.ppid !== undefined
            ? { ppid: msg.ppid, comm: msg.comm, action: "lsm_deny" }
            : { comm: msg.comm, action: "lsm_deny" },
      });
      void deps.publish(event);
      return;
    }
  }
}

function hookToSyscall(hook: string): string {
  switch (hook) {
    case "file_open":
      return "openat";
    case "bprm_check_security":
      return "execve";
    case "socket_connect":
      return "connect";
    default:
      return hook;
  }
}
