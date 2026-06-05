/**
 * End-to-end verification for the uprobe probe + native judge.
 *
 * Same harness shape as the sibling eBPF e2e (probes/ebpf/verify-e2e.mjs).
 * Expects compiled `.js` artifacts (run `npm run build` before invoking).
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
const { createUprobeProbe } = await import(path.join(HERE, "index.js"));

const stateDir = process.env.SENTINEL_STATE_DIR ?? "/tmp/sentinel-uprobe-e2e-state";
fs.mkdirSync(stateDir, { recursive: true });
const eventsDir = path.join(stateDir, "probe-events");
if (fs.existsSync(eventsDir)) {
  for (const f of fs.readdirSync(eventsDir)) fs.rmSync(path.join(eventsDir, f));
}

const runtime = createNoopRuntime({
  stateDir,
  logger: {
    debug: (m, ...a) => console.error("DEBUG", m, ...a),
    info: (m, ...a) => console.error("INFO ", m, ...a),
    warn: (m, ...a) => console.error("WARN ", m, ...a),
    error: (m, ...a) => console.error("ERROR", m, ...a),
  },
});

const sentinel = startSentinel(runtime);
sentinel.registerJudge(createNativeJudge());
await sentinel.registerProbe(createUprobeProbe());

console.error("--- waiting for uprobe attach (4s) ---");
await new Promise((r) => setTimeout(r, 4000));

console.error("--- triggering representative syscalls ---");
const triggers = [
  ["/usr/bin/cat", ["/etc/shadow"]],
  ["/usr/bin/ls", ["/etc"]],
  ["/bin/echo", ["hello"]],
];
for (const [bin, argv] of triggers) {
  try {
    execSync(`${bin} ${argv.join(" ")}`, { stdio: "pipe" });
  } catch {
    // expected for cat /etc/shadow (permission denied)
  }
}

console.error("--- waiting 2s for events to flush ---");
await new Promise((r) => setTimeout(r, 2000));
await sentinel.stop();

let events = 0;
let verdicts = 0;
const blocks = [];
const sources = new Set();
for (const f of fs.readdirSync(eventsDir)) {
  const lines = fs
    .readFileSync(path.join(eventsDir, f), "utf8")
    .trim()
    .split("\n")
    .filter(Boolean);
  for (const line of lines) {
    const r = JSON.parse(line);
    if (r.kind === "event") {
      events++;
      if (r.source) sources.add(r.source);
    }
    if (r.kind === "verdict") {
      verdicts++;
      if (r.final?.action === "block") blocks.push(r);
    }
  }
}

console.error("---");
console.error(
  `events=${events} verdicts=${verdicts} blocks=${blocks.length} sources=${[
    ...sources,
  ].join(",")}`,
);
for (const b of blocks.slice(0, 5)) {
  console.error("BLOCK:", JSON.stringify(b.final, null, 2));
}

if (!sources.has("uprobe")) {
  console.error("FAIL: no events sourced from uprobe");
  process.exit(1);
}
if (blocks.length === 0) {
  console.error("FAIL: expected at least one BLOCK verdict for /etc/shadow");
  process.exit(1);
}
console.error("PASS");
process.exit(0);
