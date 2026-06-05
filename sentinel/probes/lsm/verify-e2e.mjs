/**
 * End-to-end verification for the LSM enforce probe.
 *
 * Designed to be run INSIDE a privileged Linux container built from the
 * sibling Dockerfile. Requires kernel ≥ 5.7 with CONFIG_BPF_LSM=y and `bpf`
 * in the active LSMs (kernel cmdline `lsm=...,bpf` or `kernel.lsm` sysctl).
 *
 * Workflow:
 *   1. Start sentinel + native judge + ebpf probe (to source the first event)
 *      + lsm probe (to enforce subsequent ones).
 *   2. cat /etc/shadow #1 → ebpf tracepoint fires → native judge blocks →
 *      lsm loader translates verdict → BPF policy_map gets entry.
 *   3. cat /etc/shadow #2 → LSM file_open hook denies in-kernel → deny
 *      event observed.
 *
 * Exit code 0 means both verdict and deny were observed.
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
const { createEbpfProbe } = await import(
  path.join(SENTINEL_ROOT, "probes/ebpf/index.js")
);
const { createLsmProbe } = await import(path.join(HERE, "index.js"));

const stateDir = process.env.SENTINEL_STATE_DIR ?? "/tmp/sentinel-lsm-e2e-state";
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
await sentinel.registerProbe(createEbpfProbe());
const lsmRunnerBin = path.join(HERE, "runner", "dist", "lsm-runner");
await sentinel.registerProbe(
  createLsmProbe({ runnerBin: lsmRunnerBin, policyTtlSeconds: 60 }),
);

console.error("--- waiting 4s for probes to attach ---");
await new Promise((r) => setTimeout(r, 4000));

console.error("--- attempt 1: cat /etc/shadow (expect verdict block, no kernel deny) ---");
try {
  execSync("/usr/bin/cat /etc/shadow", { stdio: "pipe" });
} catch {
  // expected
}

console.error("--- waiting 1.5s for policy upsert to propagate ---");
await new Promise((r) => setTimeout(r, 1500));

console.error("--- attempt 2: cat /etc/shadow (expect LSM deny event) ---");
try {
  execSync("/usr/bin/cat /etc/shadow", { stdio: "pipe" });
} catch {
  // expected
}

console.error("--- waiting 2s for events to flush ---");
await new Promise((r) => setTimeout(r, 2000));
await sentinel.stop();

let events = 0;
let verdicts = 0;
const blocks = [];
const denyEvents = [];
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
      if (r.source === "lsm") denyEvents.push(r);
    }
    if (r.kind === "verdict") {
      verdicts++;
      if (r.final?.action === "block") blocks.push(r);
    }
  }
}

console.error("---");
console.error(
  `events=${events} verdicts=${verdicts} blocks=${blocks.length} ` +
    `lsm_denies=${denyEvents.length} sources=${[...sources].join(",")}`,
);
for (const b of blocks.slice(0, 5)) {
  console.error("BLOCK:", JSON.stringify(b.final, null, 2));
}
for (const d of denyEvents.slice(0, 5)) {
  console.error("LSM_DENY:", JSON.stringify(d, null, 2));
}

if (blocks.length === 0) {
  console.error("FAIL: expected at least one BLOCK verdict for /etc/shadow");
  process.exit(1);
}
if (denyEvents.length === 0) {
  console.error("FAIL: expected at least one LSM deny event on second attempt");
  process.exit(1);
}
console.error("PASS");
process.exit(0);
