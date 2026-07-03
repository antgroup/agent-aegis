import { startSentinel, } from "./index.js";
import { createL1BridgeJudge } from "./judges/l1-bridge.js";
import { createNativeJudge } from "./judges/native.js";
/**
 * Dynamically import a probe factory by module specifier. The kernel probes
 * are excluded from the OpenClaw plugin package, so the module may not exist —
 * in that case log at info and return null so sentinel keeps running. Hermes
 * ships the probe dirs, so there the import resolves and probes work as before.
 */
async function loadProbeFactory(specifier, exportName, logger) {
    try {
        const mod = (await import(specifier));
        const factory = mod[exportName];
        return typeof factory === "function" ? factory : null;
    }
    catch (err) {
        logger.info(`[agent-aegis] ${exportName} unavailable (kernel probes not bundled here — run standalone): ${String(err)}`);
        return null;
    }
}
/**
 * Start sentinel against an already-constructed runtime: register the
 * `l1-bridge` + `native` judges, then attach whichever probes
 * (`ebpf` / `uprobe` / `lsm`) the runtime's config enables. Probe failures are
 * logged, never thrown — sentinel keeps running with the rest.
 */
export async function startSentinelRuntime(runtime, engine, opts) {
    // Read eventQueue and attribution config and merge into opts
    let eventQueueCfg;
    let attributionCfg;
    let contextBufferCfg;
    try {
        const config = await runtime.readConfig();
        eventQueueCfg = readEventQueueConfig(config);
        attributionCfg = readAttributionConfig(config);
        contextBufferCfg = readContextConfig(config);
    }
    catch {
        // Config read is optional; defaults will apply.
    }
    const sentinelOpts = {
        ...opts,
        eventQueue: eventQueueCfg ?? opts?.eventQueue,
        attribution: attributionCfg ?? opts?.attribution,
        context: { buffer: contextBufferCfg ?? opts?.context?.buffer },
    };
    const sentinel = startSentinel(runtime, sentinelOpts);
    sentinel.registerJudge(createL1BridgeJudge(engine));
    let nativeCfg = {};
    try {
        nativeCfg = _internalReadNativeJudgeConfig(await runtime.readConfig());
    }
    catch (err) {
        runtime.logger.warn(`[agent-aegis] native judge config read failed; using defaults: ${String(err)}`);
    }
    sentinel.registerJudge(createNativeJudge({
        sensitivePathPatterns: nativeCfg.sensitivePathPatterns,
        scratchDirPatterns: nativeCfg.scratchDirPatterns,
        mode: nativeCfg.mode,
    }));
    try {
        const config = await runtime.readConfig();
        warnIfLegacyFrida(config, runtime.logger);
        const ebpfCfg = readEbpfConfig(config);
        if (ebpfCfg.enabled) {
            const createEbpfProbe = await loadProbeFactory("./probes/ebpf/index.js", "createEbpfProbe", runtime.logger);
            if (createEbpfProbe) {
                await sentinel.registerProbe(createEbpfProbe({
                    pythonBin: ebpfCfg.pythonBin,
                    runnerScript: ebpfCfg.runnerScript,
                    runnerBin: ebpfCfg.runnerBin,
                    lifecycle: ebpfCfg.lifecycle,
                }));
            }
        }
        const uprobeCfg = readUprobeConfig(config);
        if (uprobeCfg.enabled) {
            const createUprobeProbe = await loadProbeFactory("./probes/uprobe/index.js", "createUprobeProbe", runtime.logger);
            if (createUprobeProbe) {
                await sentinel.registerProbe(createUprobeProbe({
                    pythonBin: uprobeCfg.pythonBin,
                    runnerScript: uprobeCfg.runnerScript,
                    runnerBin: uprobeCfg.runnerBin,
                    targets: uprobeCfg.targets,
                    libcPath: uprobeCfg.libcPath,
                    opensslPath: uprobeCfg.opensslPath,
                }));
            }
        }
        const lsmCfg = readLsmConfig(config);
        if (lsmCfg.enabled) {
            const createLsmProbe = await loadProbeFactory("./probes/lsm/index.js", "createLsmProbe", runtime.logger);
            if (createLsmProbe) {
                await sentinel.registerProbe(createLsmProbe({
                    runnerBin: lsmCfg.runnerBin,
                    policyTtlSeconds: lsmCfg.policyTtlSeconds,
                    maxEntries: lsmCfg.maxEntries,
                    minSeverity: lsmCfg.minSeverity,
                    socketPath: lsmCfg.socketPath,
                    stateDir: runtime.getStateDir(),
                }));
            }
        }
    }
    catch (err) {
        runtime.logger.warn(`[agent-aegis] probe wiring failed; sentinel keeps running: ${String(err)}`);
    }
    return sentinel;
}
function warnIfLegacyFrida(config, logger) {
    const probes = (config.probes ?? {});
    const frida = probes.frida;
    if (frida && frida.enabled === true) {
        logger.warn(`[agent-aegis] probes.frida is removed in M9. Falling back silently. ` +
            `Migrate to probes.uprobe + probes.lsm — see SENTINEL_M9_PLAN.md.`);
    }
}
function readEbpfConfig(config) {
    const probes = (config.probes ?? {});
    const ebpf = (probes.ebpf ?? {});
    const enabled = ebpf.enabled === true;
    const pythonBin = typeof ebpf.pythonBin === "string" ? ebpf.pythonBin : undefined;
    const runnerScript = typeof ebpf.runnerScript === "string" ? ebpf.runnerScript : undefined;
    const runnerBin = typeof ebpf.runnerBin === "string" ? ebpf.runnerBin : undefined;
    const lifecycle = ebpf.lifecycle === true ? true : undefined;
    return { enabled, pythonBin, runnerScript, runnerBin, lifecycle };
}
function readUprobeConfig(config) {
    const probes = (config.probes ?? {});
    const u = (probes.uprobe ?? {});
    const enabled = u.enabled === true;
    const pythonBin = typeof u.pythonBin === "string" ? u.pythonBin : undefined;
    const runnerScript = typeof u.runnerScript === "string" ? u.runnerScript : undefined;
    const runnerBin = typeof u.runnerBin === "string" ? u.runnerBin : undefined;
    const libcPath = typeof u.libcPath === "string" ? u.libcPath : undefined;
    const opensslPath = typeof u.opensslPath === "string" ? u.opensslPath : undefined;
    const rawTargets = u.targets;
    const targets = Array.isArray(rawTargets)
        ? rawTargets.filter((t) => t === "execve" ||
            t === "openat" ||
            t === "connect" ||
            t === "SSL_write" ||
            t === "SSL_read")
        : undefined;
    return { enabled, pythonBin, runnerScript, runnerBin, targets, libcPath, opensslPath };
}
function readLsmConfig(config) {
    const probes = (config.probes ?? {});
    const l = (probes.lsm ?? {});
    const enabled = l.enabled === true;
    const runnerBin = typeof l.runnerBin === "string" ? l.runnerBin : undefined;
    const policyTtlSeconds = typeof l.policyTtlSeconds === "number" && l.policyTtlSeconds > 0
        ? l.policyTtlSeconds
        : undefined;
    const maxEntries = typeof l.maxEntries === "number" && l.maxEntries > 0 ? l.maxEntries : undefined;
    const minSeverity = l.minSeverity === "high" || l.minSeverity === "critical" ? l.minSeverity : undefined;
    const socketPath = typeof l.socketPath === "string" ? l.socketPath : undefined;
    return { enabled, runnerBin, policyTtlSeconds, maxEntries, minSeverity, socketPath };
}
function readEventQueueConfig(config) {
    const sentinel = (config.sentinel ?? {});
    const eq = (sentinel.eventQueue ?? {});
    const maxDepth = typeof eq.maxDepth === "number" && eq.maxDepth > 0 ? eq.maxDepth : undefined;
    const sampleRate = typeof eq.sampleRate === "number" && eq.sampleRate >= 0 && eq.sampleRate <= 1
        ? eq.sampleRate
        : undefined;
    if (maxDepth === undefined && sampleRate === undefined)
        return undefined;
    const out = {};
    if (maxDepth !== undefined)
        out.maxDepth = maxDepth;
    if (sampleRate !== undefined)
        out.sampleRate = sampleRate;
    return out;
}
function readAttributionConfig(config) {
    const sentinel = (config.sentinel ?? {});
    const a = (sentinel.attribution ?? {});
    const num = (v, min = 0) => typeof v === "number" && v > min ? v : undefined;
    const correlationWindowMs = num(a.correlationWindowMs);
    const causalWindowMs = num(a.causalWindowMs);
    const maxTreeNodes = num(a.maxTreeNodes);
    const staleNodeMs = num(a.staleNodeMs);
    const pruneNodeMs = num(a.pruneNodeMs);
    const maxCausalPerSession = num(a.maxCausalPerSession);
    if (correlationWindowMs === undefined &&
        causalWindowMs === undefined &&
        maxTreeNodes === undefined &&
        staleNodeMs === undefined &&
        pruneNodeMs === undefined &&
        maxCausalPerSession === undefined) {
        return undefined;
    }
    const out = {};
    if (correlationWindowMs !== undefined)
        out.correlationWindowMs = correlationWindowMs;
    if (causalWindowMs !== undefined)
        out.causalWindowMs = causalWindowMs;
    if (maxTreeNodes !== undefined)
        out.maxTreeNodes = maxTreeNodes;
    if (staleNodeMs !== undefined)
        out.staleNodeMs = staleNodeMs;
    if (pruneNodeMs !== undefined)
        out.pruneNodeMs = pruneNodeMs;
    if (maxCausalPerSession !== undefined)
        out.maxCausalPerSession = maxCausalPerSession;
    return out;
}
function readContextConfig(config) {
    const sentinel = (config.sentinel ?? {});
    const ctx = (sentinel.context ?? {});
    const buf = (ctx.buffer ?? {});
    const num = (v, min = 0) => typeof v === "number" && v > min ? v : undefined;
    const maxPerSession = num(buf.maxPerSession);
    const maxSessions = num(buf.maxSessions);
    const sessionTtlMs = num(buf.sessionTtlMs);
    if (maxPerSession === undefined && maxSessions === undefined && sessionTtlMs === undefined) {
        return undefined;
    }
    const out = {};
    if (maxPerSession !== undefined)
        out.maxPerSession = maxPerSession;
    if (maxSessions !== undefined)
        out.maxSessions = maxSessions;
    if (sessionTtlMs !== undefined)
        out.sessionTtlMs = sessionTtlMs;
    return out;
}
/**
 * Translate `userConfig.nativeJudge` into RegExp arrays for createNativeJudge.
 * Strings are matched as literal substrings of the syscall path (escaped),
 * with word boundary `\b` on each end so `/etc/shadow` doesn't accidentally
 * match `/etc/shadow.bak`.
 *
 * Exported only for unit testing — not part of the public API.
 */
export function _internalReadNativeJudgeConfig(config) {
    const nj = (config.nativeJudge ?? {});
    const sensitivePathPatterns = toRegexpList(nj.sensitivePaths, /* anchorStart */ false);
    const scratchDirPatterns = toRegexpList(nj.scratchDirs, /* anchorStart */ true);
    const out = {};
    if (sensitivePathPatterns.length > 0)
        out.sensitivePathPatterns = sensitivePathPatterns;
    if (scratchDirPatterns.length > 0)
        out.scratchDirPatterns = scratchDirPatterns;
    if (nj.mode === "observe" || nj.mode === "enforce")
        out.mode = nj.mode;
    return out;
}
function toRegexpList(raw, anchorStart) {
    if (!Array.isArray(raw))
        return [];
    const out = [];
    for (const entry of raw) {
        if (typeof entry !== "string" || entry.length === 0)
            continue;
        const escaped = entry.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
        out.push(new RegExp(anchorStart ? `^${escaped}` : `${escaped}\\b`));
    }
    return out;
}
