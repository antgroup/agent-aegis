export function parseLsmRunnerMessage(line) {
    const trimmed = line.trim();
    if (!trimmed)
        return null;
    let raw;
    try {
        raw = JSON.parse(trimmed);
    }
    catch {
        return null;
    }
    if (!raw || typeof raw !== "object")
        return null;
    const r = raw;
    switch (r.kind) {
        case "ready":
            return parseReady(r);
        case "deny":
            return parseDeny(r);
        case "log":
            return parseLog(r);
        default:
            return null;
    }
}
function parseReady(r) {
    if (!Array.isArray(r.hooks))
        return null;
    if (!r.hooks.every((s) => typeof s === "string"))
        return null;
    return { kind: "ready", hooks: r.hooks };
}
function parseDeny(r) {
    if (typeof r.hook !== "string")
        return null;
    if (typeof r.match !== "string")
        return null;
    const pid = typeof r.pid === "number" ? r.pid : 0;
    const ts = typeof r.ts === "number" ? r.ts : Date.now();
    const out = { kind: "deny", hook: r.hook, match: r.match, pid, ts };
    if (typeof r.ppid === "number")
        out.ppid = r.ppid;
    if (typeof r.comm === "string")
        out.comm = r.comm;
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
