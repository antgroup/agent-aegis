/**
 * Continuous OBSERVE-mode eBPF runner for the interactive lab container.
 *
 * Same pipeline as live-observe.mjs (sentinel + eBPF probe + native judge in
 * `mode: "observe"`, forwarding every detection into
 * `<SENTINEL_STATE_DIR>/defense-events.jsonl` — the file the WebUI tails), but
 * instead of triggering a fixed demo and exiting, it stays attached and observes
 * whatever syscalls the user triggers in the container, until SIGINT/SIGTERM.
 *
 * It does NOT wipe the events file on start: the L1 runtimes' events are merged
 * into the same file (see docker/interactive-entry.sh), so the lab accumulates
 * OpenClaw / Hermes / eBPF detections together in one WebUI.
 *
 * Run inside the privileged lab container; backgrounded by interactive-entry.sh.
 */

import path from "node:path";
import fs from "node:fs";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SENTINEL_ROOT = path.resolve(HERE, "..", "..");

const { startSentinel } = await import(path.join(SENTINEL_ROOT, "index.js"));
const { createNoopRuntime } = await import(
  path.join(SENTINEL_ROOT, "runtime/noop-runtime.js")
);
const { createNativeJudge } = await import(
  path.join(SENTINEL_ROOT, "judges/native.js")
);
const { appendWebuiDefenseEvent } = await import(
  path.join(SENTINEL_ROOT, "channel/webui-bridge.js")
);
const { createEbpfProbe } = await import(path.join(HERE, "index.js"));

const stateDir = process.env.SENTINEL_STATE_DIR ?? "/state";
fs.mkdirSync(stateDir, { recursive: true });
const eventsFile = path.join(stateDir, "defense-events.jsonl");

const runtime = createNoopRuntime({
  stateDir,
  logger: {
    debug: () => {},
    info: (m, ...a) => console.error("INFO ", m, ...a),
    warn: (m, ...a) => console.error("WARN ", m, ...a),
    error: (m, ...a) => console.error("ERROR", m, ...a),
  },
  // Forward every kernel detection into the WebUI's defense-events.jsonl.
  onSentinelEvent: (event, verdict) => {
    try {
      appendWebuiDefenseEvent(eventsFile, event, verdict);
    } catch (err) {
      console.error("[observe-forever] forward failed:", err);
    }
  },
});

const sentinel = startSentinel(runtime);
// Whole lab is observe-only: detect + forward to the WebUI, never intercept.
sentinel.registerJudge(createNativeJudge({ mode: "observe" }));
// Force the SYSTEM python3 (which has python3-bpfcc). The PATH puts the Hermes
// venv first, and that interpreter has no bcc — see docker/Dockerfile.interactive.
await sentinel.registerProbe(
  createEbpfProbe({ pythonBin: process.env.EBPF_PYTHON_BIN ?? "/usr/bin/python3" }),
);

console.error(`[observe-forever] eBPF probe attached; observing → ${eventsFile}`);
console.error("[observe-forever] running until SIGINT/SIGTERM …");

let stopping = false;
async function shutdown(sig) {
  if (stopping) return;
  stopping = true;
  console.error(`[observe-forever] ${sig} received; stopping sentinel …`);
  try {
    await sentinel.stop();
  } catch (err) {
    console.error("[observe-forever] stop error:", err);
  }
  process.exit(0);
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

// Keep the event loop alive indefinitely; the probe runs in the background.
await new Promise(() => {});
