/**
 * Live verification that the **Hermes RPC path** starts the eBPF probe — the
 * same way a real Hermes install does.
 *
 * Unlike live-observe.mjs (which wires sentinel directly with a noop runtime),
 * this drives the actual `AegisRpcRuntime` from `rpc-handlers.js` — i.e. what
 * `node rpc-server.js` runs when the Hermes Python plugin spawns it. We call
 * `init(...)` with `probes.ebpf.enabled` + `nativeJudge.mode: observe`, which
 * goes through `createHermesRuntime` → `startSentinelRuntime` → eBPF probe.
 *
 * Then `cat /etc/shadow` is triggered and we assert it was OBSERVED (not
 * blocked) and forwarded to `<stateDir>/defense-events.jsonl` (the file the
 * Hermes WebUI tails).
 *
 * Run inside the privileged BCC container (sibling Dockerfile); driven by
 * observe-hermes.sh.
 */

import { execSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(HERE, "..", "..", "..");

const { AegisRpcRuntime } = await import(path.join(REPO_ROOT, "rpc-handlers.js"));

const stateDir = process.env.SENTINEL_STATE_DIR ?? "/tmp/agent-aegis-hermes-state";
fs.mkdirSync(stateDir, { recursive: true });
const eventsFile = path.join(stateDir, "defense-events.jsonl");
fs.rmSync(eventsFile, { force: true });
fs.rmSync(path.join(stateDir, "probe-events"), { recursive: true, force: true });

const rt = new AegisRpcRuntime();
console.error("--- init() via the real Hermes RPC runtime (ebpf observe enabled) ---");
await rt.init({
  config: {
    allDefensesEnabled: true,
    defaultBlockingMode: "observe",
    nativeJudge: { mode: "observe" },
    probes: { ebpf: { enabled: true } },
  },
  stateDir,
  pluginRootDir: REPO_ROOT,
  protectedRoots: [],
});

// init() returns before the probe attaches (fire-and-forget, like OpenClaw).
console.error("--- waiting for eBPF probe to attach (5s) ---");
await new Promise((r) => setTimeout(r, 5000));

console.error("--- triggering representative syscalls (observe mode) ---");
for (const cmd of ["/usr/bin/cat /etc/shadow", "/usr/bin/ls /etc", "/bin/echo hi"]) {
  try {
    execSync(cmd, { stdio: "pipe" });
  } catch {
    // cat /etc/shadow exits non-zero (kernel denies the read for non-root) —
    // that's the OS, not us. We only care that the openat/execve was observed.
  }
}

console.error("--- waiting 2s for events to flush ---");
await new Promise((r) => setTimeout(r, 2000));
await rt.stop();

const lines = fs.existsSync(eventsFile)
  ? fs
      .readFileSync(eventsFile, "utf8")
      .trim()
      .split("\n")
      .filter(Boolean)
      .map((l) => JSON.parse(l))
  : [];
const nativeObserved = lines.filter(
  (e) => e.result === "observed" && String(e.defense).startsWith("native:"),
);
const nativeBlocked = lines.filter(
  (e) => e.result === "blocked" && String(e.defense).startsWith("native:"),
);

console.error("---");
console.error(
  `webui_events=${lines.length} native_observed=${nativeObserved.length} native_blocked=${nativeBlocked.length}`,
);
for (const e of nativeObserved.slice(0, 5)) {
  console.error(
    "OBSERVED→WebUI:",
    JSON.stringify({ defense: e.defense, result: e.result, commandText: e.commandText }),
  );
}

if (nativeBlocked.length > 0) {
  console.error(`FAIL: observe mode must not block, but saw ${nativeBlocked.length} block(s)`);
  process.exit(1);
}
if (nativeObserved.length === 0) {
  console.error(
    "FAIL: the Hermes RPC init did not produce eBPF observe events in defense-events.jsonl",
  );
  process.exit(1);
}
console.error("PASS (Hermes RPC init started eBPF; observed, not blocked; forwarded to WebUI)");
process.exit(0);
