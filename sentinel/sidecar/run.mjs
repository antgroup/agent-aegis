/**
 * Per-agent sentinel sidecar runner (L2/L3, standalone).
 *
 * One self-contained, config-driven process that runs the kernel-level defense
 * for ONE agent independently of the L1 plugin:
 *   - reads a dedicated sentinel config file (NOT the L1 config),
 *   - registers the native judge in the configured mode (observe / enforce),
 *   - attaches whichever probes (ebpf / uprobe / lsm) the config enables,
 *   - forwards every detection into <stateDir>/defense-events.jsonl — the same
 *     file that agent's WebUI tails — so each agent sees its own L1 + L2/L3.
 *
 * Why standalone (vs in-plugin): eBPF needs root and (for OpenClaw) the plugin
 * scanner blocks child_process. So L2/L3 ships as a per-agent sidecar: its own
 * install dir, its own config, its own launcher, its own events. Run as root.
 *
 * Usage:
 *   sudo node run.mjs --config <path/to/sentinel.config.json>
 *   (env overrides: SENTINEL_CONFIG, SENTINEL_STATE_DIR, EBPF_PYTHON_BIN)
 */

import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const SENTINEL_ROOT = path.resolve(HERE, ".."); // sentinel/sidecar -> sentinel/

// ---- args / config ----------------------------------------------------------
function argv(name) {
  const i = process.argv.indexOf(name);
  return i >= 0 && i + 1 < process.argv.length ? process.argv[i + 1] : undefined;
}
const configPath =
  argv("--config") ?? process.env.SENTINEL_CONFIG ?? path.join(HERE, "config.json");

let config = {};
try {
  config = JSON.parse(fs.readFileSync(configPath, "utf8"));
} catch (err) {
  console.error(`[sentinel-sidecar] cannot read config ${configPath}: ${err}`);
  process.exit(2);
}

const stateDir =
  argv("--state-dir") ??
  process.env.SENTINEL_STATE_DIR ??
  config.stateDir ??
  path.join(HERE, "state");
fs.mkdirSync(stateDir, { recursive: true });
const eventsFile = path.join(stateDir, "defense-events.jsonl");

const nj = config.nativeJudge ?? {};
const probesCfg = config.probes ?? {};
const mode = nj.mode === "enforce" ? "enforce" : "observe";

// ---- sentinel wiring --------------------------------------------------------
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

/** String patterns → RegExp (mirrors bootstrap.ts toRegexpList). */
function toRegexps(raw, anchorStart) {
  if (!Array.isArray(raw)) return undefined;
  const out = [];
  for (const entry of raw) {
    if (typeof entry !== "string" || entry.length === 0) continue;
    const esc = entry.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out.push(new RegExp(anchorStart ? `^${esc}` : `${esc}\\b`));
  }
  return out.length ? out : undefined;
}

/** Dynamic-import a probe factory; tolerate absence (log + null). */
async function loadProbeFactory(specifier, exportName) {
  try {
    const mod = await import(path.join(SENTINEL_ROOT, specifier));
    const f = mod[exportName];
    return typeof f === "function" ? f : null;
  } catch (err) {
    console.error(`[sentinel-sidecar] ${exportName} unavailable: ${err}`);
    return null;
  }
}

const runtime = createNoopRuntime({
  stateDir,
  logger: {
    debug: () => {},
    info: (m, ...a) => console.error("INFO ", m, ...a),
    warn: (m, ...a) => console.error("WARN ", m, ...a),
    error: (m, ...a) => console.error("ERROR", m, ...a),
  },
  onSentinelEvent: (event, verdict) => {
    try {
      appendWebuiDefenseEvent(eventsFile, event, verdict);
    } catch (err) {
      console.error("[sentinel-sidecar] forward failed:", err);
    }
  },
});

const sentinel = startSentinel(runtime);
sentinel.registerJudge(
  createNativeJudge({
    mode,
    sensitivePathPatterns: toRegexps(nj.sensitivePaths, false),
    scratchDirPatterns: toRegexps(nj.scratchDirs, true),
  }),
);

const enabled = [];
if (probesCfg.ebpf?.enabled) {
  const f = await loadProbeFactory("probes/ebpf/index.js", "createEbpfProbe");
  if (f) {
    await sentinel.registerProbe(
      f({
        pythonBin:
          probesCfg.ebpf.pythonBin ?? process.env.EBPF_PYTHON_BIN ?? "python3",
        runnerScript: probesCfg.ebpf.runnerScript,
        runnerBin: probesCfg.ebpf.runnerBin,
      }),
    );
    enabled.push("ebpf");
  }
}
if (probesCfg.uprobe?.enabled) {
  const f = await loadProbeFactory("probes/uprobe/index.js", "createUprobeProbe");
  if (f) {
    await sentinel.registerProbe(
      f({
        pythonBin:
          probesCfg.uprobe.pythonBin ?? process.env.EBPF_PYTHON_BIN ?? "python3",
        runnerScript: probesCfg.uprobe.runnerScript,
        runnerBin: probesCfg.uprobe.runnerBin,
        targets: probesCfg.uprobe.targets,
        libcPath: probesCfg.uprobe.libcPath,
        opensslPath: probesCfg.uprobe.opensslPath,
      }),
    );
    enabled.push("uprobe");
  }
}
if (probesCfg.lsm?.enabled) {
  const f = await loadProbeFactory("probes/lsm/index.js", "createLsmProbe");
  if (f) {
    await sentinel.registerProbe(
      f({
        runnerBin: probesCfg.lsm.runnerBin,
        policyTtlSeconds: probesCfg.lsm.policyTtlSeconds,
        maxEntries: probesCfg.lsm.maxEntries,
        minSeverity: probesCfg.lsm.minSeverity,
        socketPath: probesCfg.lsm.socketPath,
        stateDir,
      }),
    );
    enabled.push("lsm");
  }
}

if (enabled.length === 0) {
  console.error(
    "[sentinel-sidecar] no probes enabled in config.probes — nothing to observe; " +
      "set probes.ebpf.enabled (and/or uprobe/lsm) to true. Exiting.",
  );
  process.exit(3);
}

console.error(
  `[sentinel-sidecar] mode=${mode} probes=[${enabled.join(",")}] ` +
    `events → ${eventsFile} (config: ${configPath})`,
);
console.error("[sentinel-sidecar] running until SIGINT/SIGTERM …");

let stopping = false;
async function shutdown(sig) {
  if (stopping) return;
  stopping = true;
  console.error(`[sentinel-sidecar] ${sig}; stopping …`);
  try {
    await sentinel.stop();
  } catch (err) {
    console.error("[sentinel-sidecar] stop error:", err);
  }
  process.exit(0);
}
process.on("SIGINT", () => shutdown("SIGINT"));
process.on("SIGTERM", () => shutdown("SIGTERM"));

await new Promise(() => {}); // keep alive; probes run in the background
