/**
 * Parse an arbitrary payload received from the agent script into an
 * AgentMessage. Returns null when the payload is malformed; the caller is
 * expected to log and drop. Defensive on purpose — the Frida script runs in
 * an arbitrary process and could be tampered with.
 */
export function parseAgentMessage(raw) {
    if (!raw || typeof raw !== "object")
        return null;
    const r = raw;
    const kind = r.kind;
    switch (kind) {
        case "syscall":
            return parseSyscall(r);
        case "log":
            return parseLog(r);
        case "error":
            return parseError(r);
        case "ready":
            return parseReady(r);
        case "unsupported":
            return parseUnsupported(r);
        case "decision_request":
            return parseDecisionRequest(r);
        case "decision_response":
            return parseDecisionResponse(r);
        default:
            return null;
    }
}
function parseSyscall(r) {
    if (typeof r.syscall !== "string")
        return null;
    const pid = typeof r.pid === "number" ? r.pid : 0;
    const ts = typeof r.ts === "number" ? r.ts : Date.now();
    const out = { kind: "syscall", syscall: r.syscall, pid, ts };
    if (Array.isArray(r.argv) && r.argv.every((s) => typeof s === "string")) {
        out.argv = r.argv;
    }
    if (typeof r.path === "string")
        out.path = r.path;
    if (typeof r.addr === "string")
        out.addr = r.addr;
    if (r.extra && typeof r.extra === "object" && !Array.isArray(r.extra)) {
        out.extra = r.extra;
    }
    return out;
}
function parseLog(r) {
    const level = r.level;
    if (level !== "debug" && level !== "info" && level !== "warn" && level !== "error")
        return null;
    if (typeof r.message !== "string")
        return null;
    return { kind: "log", level, message: r.message };
}
function parseError(r) {
    if (typeof r.where !== "string" || typeof r.message !== "string")
        return null;
    return { kind: "error", where: r.where, message: r.message };
}
function parseReady(r) {
    if (!Array.isArray(r.hookedTargets))
        return null;
    if (!r.hookedTargets.every((s) => typeof s === "string"))
        return null;
    return { kind: "ready", hookedTargets: r.hookedTargets };
}
function parseUnsupported(r) {
    if (typeof r.platform !== "string")
        return null;
    return { kind: "unsupported", platform: r.platform };
}
function parseDecisionRequest(r) {
    if (typeof r.id !== "string" || typeof r.syscall !== "string")
        return null;
    const pid = typeof r.pid === "number" ? r.pid : 0;
    const out = { kind: "decision_request", id: r.id, syscall: r.syscall, pid };
    if (Array.isArray(r.argv) && r.argv.every((s) => typeof s === "string")) {
        out.argv = r.argv;
    }
    if (typeof r.path === "string")
        out.path = r.path;
    return out;
}
function parseDecisionResponse(r) {
    if (typeof r.id !== "string")
        return null;
    if (r.decision !== "allow" && r.decision !== "deny")
        return null;
    const out = { kind: "decision_response", id: r.id, decision: r.decision };
    if (typeof r.reason === "string")
        out.reason = r.reason;
    return out;
}
