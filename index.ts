import { definePluginEntry, type OpenClawPluginApi } from "./runtime-api.js";
import { clawAegisPluginConfigDefinition } from "./src/config.js";
import { createClawAegisRuntime } from "./src/handlers.js";
import { startSentinel, type SentinelHandle } from "./sentinel/index.js";
import { createL1BridgeJudge } from "./sentinel/judges/l1-bridge.js";
import { createNativeJudge } from "./sentinel/judges/native.js";
import { createEbpfProbe } from "./sentinel/probes/ebpf/index.js";
import { createUprobeProbe, type UprobeHookTarget } from "./sentinel/probes/uprobe/index.js";
import { createLsmProbe, type LsmMinSeverity } from "./sentinel/probes/lsm/index.js";
import { createOpenClawRuntime } from "./sentinel/runtime/adapters/openclaw.js";

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- handlers have heterogeneous signatures; `any` is needed for contravariance
type GenericHookHandler = (event: any, ctx: any) => any;

export function wrapHookFailOpen(
  api: OpenClawPluginApi,
  hookName: string,
  handler: GenericHookHandler,
): GenericHookHandler {
  return async (event, ctx) => {
    try {
      return await handler(event, ctx);
    } catch (error) {
      api.logger.error(
        `[claw-aegis] ${hookName} failed; fail-open keeps OpenClaw running: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return undefined;
    }
  };
}

export function wrapSyncHookFailOpen(
  api: OpenClawPluginApi,
  hookName: string,
  handler: GenericHookHandler,
): GenericHookHandler {
  return (event, ctx) => {
    try {
      return handler(event, ctx);
    } catch (error) {
      api.logger.error(
        `[claw-aegis] ${hookName} failed; fail-open keeps OpenClaw running: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
      return undefined;
    }
  };
}

export function registerClawAegisPlugin(
  api: OpenClawPluginApi,
  createRuntime: typeof createClawAegisRuntime = createClawAegisRuntime,
): void {
  try {
    const runtime = createRuntime(api);
    api.on("gateway_start", wrapHookFailOpen(api, "gateway_start", runtime.hooks.gateway_start));
    api.on(
      "message_received",
      wrapSyncHookFailOpen(api, "message_received", runtime.hooks.message_received),
    );
    api.on(
      "message_sending",
      wrapHookFailOpen(api, "message_sending", runtime.hooks.message_sending),
    );
    api.on(
      "before_prompt_build",
      wrapHookFailOpen(api, "before_prompt_build", runtime.hooks.before_prompt_build),
    );
    api.on(
      "before_dispatch",
      wrapHookFailOpen(api, "before_dispatch", runtime.hooks.before_dispatch),
    );
    api.on(
      "before_agent_reply",
      wrapHookFailOpen(api, "before_agent_reply", runtime.hooks.before_agent_reply),
    );
    api.on(
      "before_tool_call",
      wrapHookFailOpen(api, "before_tool_call", runtime.hooks.before_tool_call),
    );
    api.on(
      "after_tool_call",
      wrapSyncHookFailOpen(api, "after_tool_call", runtime.hooks.after_tool_call),
    );
    api.on(
      "before_message_write",
      wrapSyncHookFailOpen(api, "before_message_write", runtime.hooks.before_message_write),
    );
    api.on("llm_output", wrapSyncHookFailOpen(api, "llm_output", runtime.hooks.llm_output));
    api.on("agent_end", wrapSyncHookFailOpen(api, "agent_end", runtime.hooks.agent_end));
    api.on("session_end", wrapSyncHookFailOpen(api, "session_end", runtime.hooks.session_end));

    try {
      void startSentinelForOpenClaw(api, runtime.engine);
    } catch (error) {
      api.logger.warn(
        `[claw-aegis] sentinel startup failed; L1 defense continues: ${
          error instanceof Error ? error.message : String(error)
        }`,
      );
    }
  } catch (error) {
    api.logger.error(
      `[claw-aegis] register failed; fail-open keeps OpenClaw running: ${
        error instanceof Error ? error.message : String(error)
      }`,
    );
  }
}

/**
 * Bootstrap the sentinel subsystem, register its judges, and conditionally
 * attach probes based on user config.
 *
 * Judges registered unconditionally:
 *   - l1-bridge: delegates `tool_call` syscall events back to the existing
 *     AegisDefenseEngine. Dormant until a probe emits `tool_call`-shaped
 *     events.
 *   - native:    handles syscall events that L1 cannot see (e.g. /etc/shadow
 *     access via execve). Lights up the moment a probe lands.
 *
 * Probes (opt-in, Linux only):
 *   - ebpf:    syscall tracepoint observer (M5 / system-wide)
 *   - uprobe:  user-space libc/openssl symbol observer (M7)
 *   - lsm:     in-kernel enforce — denies high-severity verdicts (M7.5)
 *
 * All probes log a warn on failure rather than throwing. A legacy
 * `probes.frida.*` block in user config is accepted but no-op'd with a warn —
 * Frida support was removed in M9.
 */
async function startSentinelForOpenClaw(
  api: OpenClawPluginApi,
  engine: Parameters<typeof createL1BridgeJudge>[0],
): Promise<SentinelHandle> {
  const runtime = createOpenClawRuntime(api);
  const sentinel = startSentinel(runtime);
  sentinel.registerJudge(createL1BridgeJudge(engine));

  let nativeCfg: ReturnType<typeof _internalReadNativeJudgeConfig> = {};
  try {
    nativeCfg = _internalReadNativeJudgeConfig(await runtime.readConfig());
  } catch (err) {
    api.logger.warn(
      `[claw-aegis] native judge config read failed; using defaults: ${String(err)}`,
    );
  }
  sentinel.registerJudge(
    createNativeJudge({
      sensitivePathPatterns: nativeCfg.sensitivePathPatterns,
      scratchDirPatterns: nativeCfg.scratchDirPatterns,
    }),
  );

  try {
    const config = await runtime.readConfig();
    warnIfLegacyFrida(config, api);
    const ebpfCfg = readEbpfConfig(config);
    if (ebpfCfg.enabled) {
      await sentinel.registerProbe(
        createEbpfProbe({
          pythonBin: ebpfCfg.pythonBin,
          runnerScript: ebpfCfg.runnerScript,
          runnerBin: ebpfCfg.runnerBin,
        }),
      );
    }
    const uprobeCfg = readUprobeConfig(config);
    if (uprobeCfg.enabled) {
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
    const lsmCfg = readLsmConfig(config);
    if (lsmCfg.enabled) {
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
  } catch (err) {
    api.logger.warn(
      `[claw-aegis] probe wiring failed; sentinel keeps running: ${String(err)}`,
    );
  }

  return sentinel;
}

function warnIfLegacyFrida(config: Record<string, unknown>, api: OpenClawPluginApi): void {
  const probes = (config.probes ?? {}) as Record<string, unknown>;
  const frida = probes.frida as Record<string, unknown> | undefined;
  if (frida && frida.enabled === true) {
    api.logger.warn(
      `[claw-aegis] probes.frida is removed in M9. Falling back silently. ` +
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
} {
  const nj = (config.nativeJudge ?? {}) as Record<string, unknown>;
  const sensitivePathPatterns = toRegexpList(nj.sensitivePaths, /* anchorStart */ false);
  const scratchDirPatterns = toRegexpList(nj.scratchDirs, /* anchorStart */ true);
  const out: ReturnType<typeof _internalReadNativeJudgeConfig> = {};
  if (sensitivePathPatterns.length > 0) out.sensitivePathPatterns = sensitivePathPatterns;
  if (scratchDirPatterns.length > 0) out.scratchDirPatterns = scratchDirPatterns;
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

export default definePluginEntry({
  id: "claw-aegis",
  name: "Claw Aegis",
  description: "Minimal safety guard plugin for prompt, tool, and tool-result hardening.",
  configSchema: clawAegisPluginConfigDefinition,
  register(api: OpenClawPluginApi) {
    registerClawAegisPlugin(api);
  },
});
