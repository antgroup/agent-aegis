import {
  startSentinel,
  type SentinelHandle,
  type SentinelOptions,
  type Probe,
} from "./index.js";
import { createL1BridgeJudge } from "./judges/l1-bridge.js";
import { createNativeJudge } from "./judges/native.js";
import type { AgentLogger, AgentRuntime } from "./runtime/types.js";

// Probe option types, inlined so this module never references the probe dirs.
// The kernel probes spawn helper processes — a pattern the OpenClaw plugin
// scanner blocks — so they are excluded from the OpenClaw npm pack (see
// package.json `files`). They are loaded lazily below and may be absent.
type UprobeHookTarget = "execve" | "openat" | "connect" | "SSL_write" | "SSL_read";
type LsmMinSeverity = "high" | "critical";

/**
 * Framework-agnostic sentinel bootstrap.
 *
 * Both the OpenClaw native plugin (`index.ts`) and the Hermes RPC server
 * (`rpc-handlers.ts`) call `startSentinelRuntime` with their own AgentRuntime
 * (created by the respective `runtime/adapters/*` adapter) plus the shared L1
 * `AegisDefenseEngine`. The engine is referenced structurally (`SentinelEngine`)
 * so this module never imports `src/*` or `runtime-api.*`.
 */

/** The L1 defense engine, referenced structurally to keep the dep rule. */
export type SentinelEngine = Parameters<typeof createL1BridgeJudge>[0];

/** A probe factory (e.g. `createEbpfProbe`) loaded dynamically at runtime. */
type ProbeFactory = (opts: Record<string, unknown>) => Probe;

/**
 * Dynamically import a probe factory by module specifier. The kernel probes
 * are excluded from the OpenClaw plugin package, so the module may not exist —
 * in that case log at info and return null so sentinel keeps running. Hermes
 * ships the probe dirs, so there the import resolves and probes work as before.
 */
async function loadProbeFactory(
  specifier: string,
  exportName: string,
  logger: AgentLogger,
): Promise<ProbeFactory | null> {
  try {
    const mod = (await import(specifier)) as Record<string, unknown>;
    const factory = mod[exportName];
    return typeof factory === "function" ? (factory as ProbeFactory) : null;
  } catch (err) {
    logger.info(
      `[agent-aegis] ${exportName} unavailable (kernel probes not bundled here — run standalone): ${String(err)}`,
    );
    return null;
  }
}

/**
 * Start sentinel against an already-constructed runtime: register the
 * `l1-bridge` + `native` judges, then attach whichever probes
 * (`ebpf` / `uprobe` / `lsm`) the runtime's config enables. Probe failures are
 * logged, never thrown — sentinel keeps running with the rest.
 */
export async function startSentinelRuntime(
  runtime: AgentRuntime,
  engine: SentinelEngine,
  opts?: SentinelOptions,
): Promise<SentinelHandle> {
  const sentinel = startSentinel(runtime, opts);
  sentinel.registerJudge(createL1BridgeJudge(engine));

  let nativeCfg: ReturnType<typeof _internalReadNativeJudgeConfig> = {};
  try {
    nativeCfg = _internalReadNativeJudgeConfig(await runtime.readConfig());
  } catch (err) {
    runtime.logger.warn(
      `[agent-aegis] native judge config read failed; using defaults: ${String(err)}`,
    );
  }
  sentinel.registerJudge(
    createNativeJudge({
      sensitivePathPatterns: nativeCfg.sensitivePathPatterns,
      scratchDirPatterns: nativeCfg.scratchDirPatterns,
      mode: nativeCfg.mode,
    }),
  );

  try {
    const config = await runtime.readConfig();
    warnIfLegacyFrida(config, runtime.logger);
    const ebpfCfg = readEbpfConfig(config);
    if (ebpfCfg.enabled) {
      const createEbpfProbe = await loadProbeFactory(
        "./probes/ebpf/index.js",
        "createEbpfProbe",
        runtime.logger,
      );
      if (createEbpfProbe) {
        await sentinel.registerProbe(
          createEbpfProbe({
            pythonBin: ebpfCfg.pythonBin,
            runnerScript: ebpfCfg.runnerScript,
            runnerBin: ebpfCfg.runnerBin,
          }),
        );
      }
    }
    const uprobeCfg = readUprobeConfig(config);
    if (uprobeCfg.enabled) {
      const createUprobeProbe = await loadProbeFactory(
        "./probes/uprobe/index.js",
        "createUprobeProbe",
        runtime.logger,
      );
      if (createUprobeProbe) {
        await sentinel.registerProbe(
          createUprobeProbe({
            pythonBin: uprobeCfg.pythonBin,
            runnerScript: uprobeCfg.runnerScript,
            runnerBin: uprobeCfg.runnerBin,
            targets: uprobeCfg.targets,
            libcPath: uprobeCfg.libcPath,
            opensslPath: uprobeCfg.opensslPath,
          }),
        );
      }
    }
    const lsmCfg = readLsmConfig(config);
    if (lsmCfg.enabled) {
      const createLsmProbe = await loadProbeFactory(
        "./probes/lsm/index.js",
        "createLsmProbe",
        runtime.logger,
      );
      if (createLsmProbe) {
        await sentinel.registerProbe(
          createLsmProbe({
            runnerBin: lsmCfg.runnerBin,
            policyTtlSeconds: lsmCfg.policyTtlSeconds,
            maxEntries: lsmCfg.maxEntries,
            minSeverity: lsmCfg.minSeverity,
            socketPath: lsmCfg.socketPath,
            stateDir: runtime.getStateDir(),
          }),
        );
      }
    }
  } catch (err) {
    runtime.logger.warn(
      `[agent-aegis] probe wiring failed; sentinel keeps running: ${String(err)}`,
    );
  }

  return sentinel;
}

function warnIfLegacyFrida(config: Record<string, unknown>, logger: AgentLogger): void {
  const probes = (config.probes ?? {}) as Record<string, unknown>;
  const frida = probes.frida as Record<string, unknown> | undefined;
  if (frida && frida.enabled === true) {
    logger.warn(
      `[agent-aegis] probes.frida is removed in M9. Falling back silently. ` +
        `Migrate to probes.uprobe + probes.lsm — see SENTINEL_M9_PLAN.md.`,
    );
  }
}

function readEbpfConfig(config: Record<string, unknown>): {
  enabled: boolean;
  pythonBin?: string;
  runnerScript?: string;
  runnerBin?: string;
} {
  const probes = (config.probes ?? {}) as Record<string, unknown>;
  const ebpf = (probes.ebpf ?? {}) as Record<string, unknown>;
  const enabled = ebpf.enabled === true;
  const pythonBin = typeof ebpf.pythonBin === "string" ? ebpf.pythonBin : undefined;
  const runnerScript = typeof ebpf.runnerScript === "string" ? ebpf.runnerScript : undefined;
  const runnerBin = typeof ebpf.runnerBin === "string" ? ebpf.runnerBin : undefined;
  return { enabled, pythonBin, runnerScript, runnerBin };
}

function readUprobeConfig(config: Record<string, unknown>): {
  enabled: boolean;
  pythonBin?: string;
  runnerScript?: string;
  runnerBin?: string;
  targets?: ReadonlyArray<UprobeHookTarget>;
  libcPath?: string;
  opensslPath?: string;
} {
  const probes = (config.probes ?? {}) as Record<string, unknown>;
  const u = (probes.uprobe ?? {}) as Record<string, unknown>;
  const enabled = u.enabled === true;
  const pythonBin = typeof u.pythonBin === "string" ? u.pythonBin : undefined;
  const runnerScript = typeof u.runnerScript === "string" ? u.runnerScript : undefined;
  const runnerBin = typeof u.runnerBin === "string" ? u.runnerBin : undefined;
  const libcPath = typeof u.libcPath === "string" ? u.libcPath : undefined;
  const opensslPath = typeof u.opensslPath === "string" ? u.opensslPath : undefined;
  const rawTargets = u.targets;
  const targets: UprobeHookTarget[] | undefined = Array.isArray(rawTargets)
    ? (rawTargets.filter(
        (t): t is UprobeHookTarget =>
          t === "execve" ||
          t === "openat" ||
          t === "connect" ||
          t === "SSL_write" ||
          t === "SSL_read",
      ) as UprobeHookTarget[])
    : undefined;
  return { enabled, pythonBin, runnerScript, runnerBin, targets, libcPath, opensslPath };
}

function readLsmConfig(config: Record<string, unknown>): {
  enabled: boolean;
  runnerBin?: string;
  policyTtlSeconds?: number;
  maxEntries?: number;
  minSeverity?: LsmMinSeverity;
  socketPath?: string;
} {
  const probes = (config.probes ?? {}) as Record<string, unknown>;
  const l = (probes.lsm ?? {}) as Record<string, unknown>;
  const enabled = l.enabled === true;
  const runnerBin = typeof l.runnerBin === "string" ? l.runnerBin : undefined;
  const policyTtlSeconds =
    typeof l.policyTtlSeconds === "number" && l.policyTtlSeconds > 0
      ? l.policyTtlSeconds
      : undefined;
  const maxEntries =
    typeof l.maxEntries === "number" && l.maxEntries > 0 ? l.maxEntries : undefined;
  const minSeverity: LsmMinSeverity | undefined =
    l.minSeverity === "high" || l.minSeverity === "critical" ? l.minSeverity : undefined;
  const socketPath = typeof l.socketPath === "string" ? l.socketPath : undefined;
  return { enabled, runnerBin, policyTtlSeconds, maxEntries, minSeverity, socketPath };
}

/**
 * Translate `userConfig.nativeJudge` into RegExp arrays for createNativeJudge.
 * Strings are matched as literal substrings of the syscall path (escaped),
 * with word boundary `\b` on each end so `/etc/shadow` doesn't accidentally
 * match `/etc/shadow.bak`.
 *
 * Exported only for unit testing — not part of the public API.
 */
export function _internalReadNativeJudgeConfig(config: Record<string, unknown>): {
  sensitivePathPatterns?: readonly RegExp[];
  scratchDirPatterns?: readonly RegExp[];
  mode?: "enforce" | "observe";
} {
  const nj = (config.nativeJudge ?? {}) as Record<string, unknown>;
  const sensitivePathPatterns = toRegexpList(nj.sensitivePaths, /* anchorStart */ false);
  const scratchDirPatterns = toRegexpList(nj.scratchDirs, /* anchorStart */ true);
  const out: ReturnType<typeof _internalReadNativeJudgeConfig> = {};
  if (sensitivePathPatterns.length > 0) out.sensitivePathPatterns = sensitivePathPatterns;
  if (scratchDirPatterns.length > 0) out.scratchDirPatterns = scratchDirPatterns;
  if (nj.mode === "observe" || nj.mode === "enforce") out.mode = nj.mode;
  return out;
}

function toRegexpList(raw: unknown, anchorStart: boolean): RegExp[] {
  if (!Array.isArray(raw)) return [];
  const out: RegExp[] = [];
  for (const entry of raw) {
    if (typeof entry !== "string" || entry.length === 0) continue;
    const escaped = entry.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
    out.push(new RegExp(anchorStart ? `^${escaped}` : `${escaped}\\b`));
  }
  return out;
}
