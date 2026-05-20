import { spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createProbeEvent } from "../../channel/event.js";
import { parseEbpfMessage } from "./messages.js";
import { detectEbpfSupport } from "./platform.js";
const PROBE_ID = "ebpf";
const EVENT_SOURCE = "ebpf";
const HERE = path.dirname(fileURLToPath(import.meta.url));
const DEFAULT_RUNNER = path.join(HERE, "runner", "probe.py");
export function createEbpfProbe(opts = {}) {
    const support = opts.platformOverride ?? detectEbpfSupport();
    const pythonBin = opts.pythonBin ?? "python3";
    const runnerScript = opts.runnerScript ?? DEFAULT_RUNNER;
    const targets = opts.targets ?? ["execve", "openat", "connect"];
    let child = null;
    let stopped = false;
    async function start(d) {
        const log = d.runtime.logger;
        if (!support.supported) {
            log.info(`[ebpf] probe skipped: ${support.reason ?? "unsupported"}`);
            return;
        }
        const args = [runnerScript, "--targets", targets.join(",")];
        try {
            child = opts.spawnOverride
                ? opts.spawnOverride(pythonBin, args)
                : spawn(pythonBin, args, { stdio: ["ignore", "pipe", "pipe"] });
        }
        catch (err) {
            log.warn(`[ebpf] spawn failed; probe disabled: ${String(err)}`);
            return;
        }
        if (!child)
            return;
        if (child.stdout)
            wireStdout(child.stdout, d);
        if (child.stderr)
            wireStderr(child.stderr, d);
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
    async function stop() {
        stopped = true;
        if (child) {
            try {
                child.kill("SIGTERM");
            }
            catch {
                // ignore
            }
            child = null;
        }
    }
    return { id: PROBE_ID, start, stop };
}
function wireStdout(stdout, deps) {
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
function wireStderr(stderr, deps) {
    stderr.on("data", (chunk) => {
        const text = typeof chunk === "string" ? chunk : chunk.toString("utf8");
        for (const line of text.split("\n")) {
            if (line.trim())
                deps.runtime.logger.warn(`[ebpf.runner] ${line}`);
        }
    });
}
/** Exported for tests. */
export function handleLine(line, deps) {
    const msg = parseEbpfMessage(line);
    if (!msg)
        return;
    routeMessage(msg, deps);
}
function routeMessage(msg, deps) {
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
function buildArgs(msg) {
    const out = {};
    if (msg.argv)
        out.argv = msg.argv;
    if (msg.path)
        out.path = msg.path;
    if (msg.addr)
        out.addr = msg.addr;
    if (msg.extra)
        Object.assign(out, msg.extra);
    return out;
}
