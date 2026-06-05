export function parseUprobeMessage(line) {
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
        case "syscall":
            return parseSyscall(r);
        case "log":
            return parseLog(r);
        default:
            return null;
    }
}
function parseReady(r) {
    if (!Array.isArray(r.probes))
        return null;
    if (!r.probes.every((p) => typeof p === "string"))
        return null;
    return { kind: "ready", probes: r.probes };
}
function parseSyscall(r) {
    if (typeof r.syscall !== "string")
        return null;
    const pid = typeof r.pid === "number" ? r.pid : 0;
    const ts = typeof r.ts === "number" ? r.ts : Date.now();
    const out = { kind: "syscall", syscall: r.syscall, pid, ts };
    if (typeof r.ppid === "number")
        out.ppid = r.ppid;
    if (Array.isArray(r.argv) && r.argv.every((s) => typeof s === "string")) {
        out.argv = r.argv;
    }
    if (typeof r.path === "string")
        out.path = r.path;
    if (typeof r.addr === "string")
        out.addr = r.addr;
    if (typeof r.comm === "string")
        out.comm = r.comm;
    if (typeof r.preview === "string")
        out.preview = r.preview;
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
