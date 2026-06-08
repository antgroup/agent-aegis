/**
 * Live OBSERVE-mode verification for the eBPF probe + native judge, with WebUI
 * forwarding.
 *
 * Same pipeline as verify-e2e.mjs but:
 *   - the native judge runs in `mode: "observe"` → every sensitive-path /
 *     kernel-escape detection is downgraded from `block` to `observe`, so the
 *     hook never intercepts (`cat /etc/shadow` is allowed to run);
 *   - each processed event+verdict is forwarded via the runtime's
 *     `onSentinelEvent` hook into `<stateDir>/defense-events.jsonl` — the exact
 *     file the WebUI tails — so the observation shows up on the Events page.
 *
 * Exit 0 means: at least one OBSERVE verdict for /etc/shadow, ZERO blocks, and
 * the WebUI events file got the observed records.
 *
 * Run inside the privileged Linux container (see Dockerfile / verify-e2e.sh);
 * driven by docker/sentinel-observe-live.sh which then serves the WebUI.
 */

import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
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

const stateDir = process.env.SENTINEL_STATE_DIR ?? "/tmp/sentinel-observe-state";
fs.mkdirSync(stateDir, { recursive: true });

// WebUI reads <stateDir>/defense-events.jsonl. Start clean so the counts and
// the UI reflect only this run.
const eventsFile = path.join(stateDir, "defense-events.jsonl");
fs.rmSync(eventsFile, { force: true });
const probeEventsDir = path.join(stateDir, "probe-events");
if (fs.existsSync(probeEventsDir)) {
  for (const f of fs.readdirSync(probeEventsDir)) {
    fs.rmSync(path.join(probeEventsDir, f));
  }
}

const runtime = createNoopRuntime({
  stateDir,
  logger: {
    debug: (m, ...a) => console.error("DEBUG", m, ...a),
    info: (m, ...a) => console.error("INFO ", m, ...a),
    warn: (m, ...a) => console.error("WARN ", m, ...a),
    error: (m, ...a) => console.error("ERROR", m, ...a),
  },
  // Forward every detection into the WebUI's defense-events.jsonl.
  onSentinelEvent: (event, verdict) =>
    appendWebuiDefenseEvent(eventsFile, event, verdict),
});

const sentinel = startSentinel(runtime);
// OBSERVE mode: detect-but-don't-block. Hook must not intercept.
sentinel.registerJudge(createNativeJudge({ mode: "observe" }));
await sentinel.registerProbe(createEbpfProbe());

console.error("--- waiting for probe to attach (4s) ---");
await new Promise((r) => setTimeout(r, 4000));

console.error("--- triggering representative syscalls (observe mode) ---");
const triggers = [
  ["/usr/bin/cat", ["/etc/shadow"]], // sensitive path → observe (NOT block)
  ["/usr/bin/ls", ["/etc"]],
  ["/bin/echo", ["hello"]],
];
for (const [bin, argv] of triggers) {
  try {
    execSync(`${bin} ${argv.join(" ")}`, { stdio: "pipe" });
  } catch {
    // `cat /etc/shadow` exits non-zero (kernel denies the read for non-root) —
    // that is the OS, not us. The point is the syscall was OBSERVED, not that
    // sentinel blocked it.
  }
}

console.error("--- waiting 2s for events to flush ---");
await new Promise((r) => setTimeout(r, 2000));
await sentinel.stop();

// Count verdicts from the raw probe-events log.
let events = 0;
let blocks = 0;
let observes = 0;
for (const f of fs.readdirSync(probeEventsDir)) {
  const lines = fs
    .readFileSync(path.join(probeEventsDir, f), "utf8")
    .trim()
    .split("\n")
    .filter(Boolean);
  for (const line of lines) {
    const r = JSON.parse(line);
    if (r.kind === "event") events++;
    if (r.kind === "verdict") {
      if (r.final?.action === "block") blocks++;
      if (r.final?.action === "observe") observes++;
    }
  }
}

// Count what actually reached the WebUI file.
const webuiLines = fs.existsSync(eventsFile)
  ? fs.readFileSync(eventsFile, "utf8").trim().split("\n").filter(Boolean)
  : [];
const webuiObserved = webuiLines
  .map((l) => JSON.parse(l))
  .filter((e) => e.result === "observed");

console.error("---");
console.error(
  `events=${events} blocks=${blocks} observes=${observes} webui_observed=${webuiObserved.length}`,
);
for (const e of webuiObserved.slice(0, 5)) {
  console.error("OBSERVED→WebUI:", JSON.stringify({ defense: e.defense, result: e.result, commandText: e.commandText }));
}

if (blocks > 0) {
  console.error(`FAIL: observe mode must not block, but saw ${blocks} block verdict(s)`);
  process.exit(1);
}
if (observes === 0 || webuiObserved.length === 0) {
  console.error("FAIL: expected at least one OBSERVE verdict for /etc/shadow forwarded to the WebUI");
  process.exit(1);
}
console.error("PASS (observed, not blocked; forwarded to WebUI)");
process.exit(0);
