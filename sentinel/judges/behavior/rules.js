import { isExternalAddr, SENSITIVE_PATTERNS } from "../../context/patterns.js";
const DEFAULT_RISKY_BINARY_PATTERNS = [
    String.raw `(^|/)curl$`,
    String.raw `(^|/)wget$`,
    String.raw `(^|/)nc$`,
    String.raw `(^|/)ncat$`,
    String.raw `(^|/)socat$`,
    String.raw `(^|/)nmap$`,
];
const DEFAULT_PERSISTENCE_PATH_PATTERNS = [
    String.raw `(^|/)\.ssh/authorized_keys$`,
    String.raw `/etc/cron\.d/`,
    String.raw `/var/spool/cron/`,
    String.raw `/etc/crontab$`,
    String.raw `/systemd/system/`,
    String.raw `/LaunchAgents/`,
    String.raw `/LaunchDaemons/`,
];
export const builtInBehaviorRules = [
    {
        id: "causal-exfil",
        defaultConfig: {
            enabled: true,
            action: "observe",
            severity: "high",
            confidence: 0.85,
        },
        evaluate: ({ event, snapshot }) => {
            if (!hasCausalFlag(event, snapshot, "exfil"))
                return null;
            return {
                reason: "behavior: causal exfil chain detected (sensitive access followed by external connection)",
            };
        },
    },
    {
        id: "causal-write-then-run",
        defaultConfig: {
            enabled: true,
            action: "observe",
            severity: "high",
            confidence: 0.8,
        },
        evaluate: ({ event, snapshot }) => {
            if (!hasCausalFlag(event, snapshot, "write_then_run"))
                return null;
            return {
                reason: "behavior: writable-directory payload staging detected (write then execute)",
            };
        },
    },
    {
        id: "sensitive-then-egress",
        defaultConfig: {
            enabled: true,
            action: "observe",
            severity: "high",
            confidence: 0.8,
            windowMs: 60_000,
            minSensitivePathHits: 1,
            minExternalConnections: 1,
        },
        evaluate: ({ event, events, config }) => {
            const window = windowEvents(events, event.timestamp, readNumber(config, "windowMs", 60_000));
            const sensitiveHits = window.filter((e) => isSensitiveOpen(e)).length;
            const externalConns = window.filter((e) => isExternalConnect(e)).length;
            const minSensitive = readNumber(config, "minSensitivePathHits", 1);
            const minExternal = readNumber(config, "minExternalConnections", 1);
            if (sensitiveHits < minSensitive || externalConns < minExternal)
                return null;
            return {
                reason: `behavior: sensitive path access and external egress in window (sensitive=${sensitiveHits}, external=${externalConns})`,
            };
        },
    },
    {
        id: "process-fanout",
        defaultConfig: {
            enabled: true,
            action: "observe",
            severity: "medium",
            confidence: 0.7,
            maxProcessFanout: 12,
        },
        evaluate: ({ snapshot, config }) => {
            const max = readNumber(config, "maxProcessFanout", 12);
            if (snapshot.features.processFanout <= max)
                return null;
            return {
                reason: `behavior: process fanout exceeded threshold (${snapshot.features.processFanout} > ${max})`,
            };
        },
    },
    {
        id: "unusual-egress",
        defaultConfig: {
            enabled: true,
            action: "observe",
            severity: "medium",
            confidence: 0.65,
            maxExternalConnections: 5,
        },
        evaluate: ({ snapshot, config }) => {
            const max = readNumber(config, "maxExternalConnections", 5);
            if (snapshot.features.externalConnCount <= max)
                return null;
            return {
                reason: `behavior: external connection count exceeded threshold (${snapshot.features.externalConnCount} > ${max})`,
            };
        },
    },
    {
        id: "unexpected-binary",
        defaultConfig: {
            enabled: true,
            action: "observe",
            severity: "medium",
            confidence: 0.65,
            binaryPatterns: DEFAULT_RISKY_BINARY_PATTERNS,
        },
        evaluate: ({ event, snapshot, config }) => {
            const patterns = readPatterns(config, "binaryPatterns", DEFAULT_RISKY_BINARY_PATTERNS);
            const currentPath = event.syscall === "execve" ? currentExecPath(event) : undefined;
            const matched = [currentPath, ...snapshot.binariesExecuted].filter(Boolean).find((path) => patterns.some((p) => p.test(path)));
            if (!matched)
                return null;
            return {
                reason: `behavior: unexpected network/scanning binary executed (${matched})`,
            };
        },
    },
    {
        id: "persistence-path",
        defaultConfig: {
            enabled: true,
            action: "observe",
            severity: "high",
            confidence: 0.75,
            pathPatterns: DEFAULT_PERSISTENCE_PATH_PATTERNS,
        },
        evaluate: ({ event, events, config }) => {
            const patterns = readPatterns(config, "pathPatterns", DEFAULT_PERSISTENCE_PATH_PATTERNS);
            const window = windowEvents(events, event.timestamp, readNumber(config, "windowMs", 60_000));
            const match = window.find((e) => e.syscall === "openat" && e.argsSummary && patterns.some((p) => p.test(e.argsSummary)));
            if (!match)
                return null;
            return {
                reason: `behavior: persistence-sensitive path touched (${match.argsSummary})`,
            };
        },
    },
    {
        id: "lateral-movement",
        defaultConfig: {
            enabled: true,
            action: "observe",
            severity: "medium",
            confidence: 0.7,
            minDistinctInternalHosts: 3,
            windowMs: 60_000,
        },
        evaluate: ({ event, events, config }) => {
            const hosts = new Set();
            for (const e of windowEvents(events, event.timestamp, readNumber(config, "windowMs", 60_000))) {
                if (e.syscall !== "connect" || !e.destAddr)
                    continue;
                if (isInternalAddr(e.destAddr))
                    hosts.add(e.destAddr);
            }
            const min = readNumber(config, "minDistinctInternalHosts", 3);
            if (hosts.size < min)
                return null;
            return {
                reason: `behavior: multiple internal hosts contacted in window (${hosts.size} >= ${min})`,
            };
        },
    },
];
function hasCausalFlag(event, snapshot, flag) {
    const current = event.meta?.causalFlags;
    return ((Array.isArray(current) && current.some((v) => v === flag)) ||
        snapshot.causalChains.includes(flag));
}
function windowEvents(events, now, windowMs) {
    const cutoff = now - windowMs;
    return events.filter((e) => e.timestamp >= cutoff && e.timestamp <= now);
}
function isSensitiveOpen(event) {
    return (event.syscall === "openat" &&
        typeof event.argsSummary === "string" &&
        SENSITIVE_PATTERNS.some((p) => p.test(event.argsSummary)));
}
function isExternalConnect(event) {
    return event.syscall === "connect" && !!event.destAddr && isExternalAddr(event.destAddr);
}
function isInternalAddr(addr) {
    if (addr === "127.0.0.1" || addr === "::1" || addr === "localhost")
        return false;
    return !isExternalAddr(addr);
}
function currentExecPath(event) {
    if (typeof event.proc?.exe === "string")
        return event.proc.exe;
    const argv = event.args?.argv;
    if (Array.isArray(argv) && typeof argv[0] === "string")
        return argv[0];
    if (typeof event.args?.path === "string")
        return event.args.path;
    return undefined;
}
function readNumber(config, key, fallback) {
    const direct = config[key];
    if (typeof direct === "number" && Number.isFinite(direct))
        return direct;
    const threshold = config.thresholds?.[key];
    if (typeof threshold === "number" && Number.isFinite(threshold))
        return threshold;
    return fallback;
}
function readPatterns(config, key, fallback) {
    const direct = config[key];
    const raw = (Array.isArray(direct) ? direct : config.patterns?.[key]) ?? fallback;
    const out = [];
    for (const v of raw) {
        if (typeof v !== "string" || v.length === 0)
            continue;
        try {
            out.push(new RegExp(v));
        }
        catch {
            // Invalid operator-provided patterns are ignored; the judge must fail open.
        }
    }
    return out;
}
