import fs from "node:fs";
import path from "node:path";
import { createRequire } from "node:module";
/**
 * Queryable SQLite index over the probe-event stream (M10 P1.3).
 *
 * The JSONL {@link ProbeEventStore} stays the durable, append-only log; this
 * index is the *queryable* projection — "what did session X / pid Y do in this
 * time range" — that the WebUI and the (future) attribution engine consume.
 *
 * Backed by the built-in `node:sqlite` (Node >= 22.5). Sentinel must still
 * *import* on older Node (OpenClaw can run on Node 20), so the module is loaded
 * lazily via createRequire inside the constructor and the whole index is
 * fail-open: if `node:sqlite` is unavailable, the index disables itself and
 * every method becomes a no-op — the JSONL log is unaffected.
 */
const require = createRequire(import.meta.url);
const EVENTS_SUBDIR = "probe-events";
const DB_FILE = "index.db";
const CREATE_SQL = `
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  ts INTEGER NOT NULL,
  source TEXT NOT NULL,
  syscall TEXT NOT NULL,
  pid INTEGER NOT NULL,
  ppid INTEGER,
  uid INTEGER,
  gid INTEGER,
  session_key TEXT,
  run_id TEXT,
  tool_name TEXT,
  comm TEXT,
  exe TEXT,
  cgroup TEXT,
  correlation_id TEXT,
  args_json TEXT,
  proc_json TEXT,
  container_json TEXT,
  net_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_key, ts);
CREATE INDEX IF NOT EXISTS idx_events_run ON events(run_id, ts);
CREATE INDEX IF NOT EXISTS idx_events_pid ON events(pid, ts);
CREATE INDEX IF NOT EXISTS idx_events_syscall ON events(syscall, ts);
CREATE TABLE IF NOT EXISTS verdicts (
  event_id TEXT NOT NULL,
  ts INTEGER NOT NULL,
  action TEXT NOT NULL,
  severity TEXT NOT NULL,
  judge_id TEXT NOT NULL,
  confidence REAL NOT NULL,
  reason TEXT,
  sources_json TEXT
);
CREATE INDEX IF NOT EXISTS idx_verdicts_event ON verdicts(event_id);
`;
export class SqliteEventIndex {
    db = null;
    insertEventStmt = null;
    insertVerdictStmt = null;
    now;
    /** Why the index is unavailable, if it is (e.g. old Node). */
    unavailableReason = null;
    constructor(opts) {
        this.now = opts.now ?? (() => Date.now());
        try {
            const { DatabaseSync } = require("node:sqlite");
            const dir = path.join(opts.stateDir, EVENTS_SUBDIR);
            fs.mkdirSync(dir, { recursive: true });
            const db = new DatabaseSync(path.join(dir, DB_FILE));
            db.exec("PRAGMA journal_mode = WAL;");
            db.exec("PRAGMA synchronous = NORMAL;");
            db.exec(CREATE_SQL);
            this.insertEventStmt = db.prepare(`INSERT OR REPLACE INTO events
          (id, ts, source, syscall, pid, ppid, uid, gid, session_key, run_id,
           tool_name, comm, exe, cgroup, correlation_id, args_json, proc_json,
           container_json, net_json)
         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`);
            this.insertVerdictStmt = db.prepare(`INSERT INTO verdicts
          (event_id, ts, action, severity, judge_id, confidence, reason, sources_json)
         VALUES (?,?,?,?,?,?,?,?)`);
            this.db = db;
        }
        catch (err) {
            this.db = null;
            this.unavailableReason = err instanceof Error ? err.message : String(err);
        }
    }
    /** True when the SQLite backend loaded; false on old Node (then a no-op). */
    get available() {
        return this.db !== null;
    }
    appendEvent(event) {
        if (!this.insertEventStmt)
            return;
        const proc = event.proc;
        this.insertEventStmt.run(event.id, event.timestamp, event.source, event.syscall, event.pid, proc?.ppid ?? null, proc?.uid ?? null, proc?.gid ?? null, event.sessionKey ?? null, event.runId ?? null, event.toolName ?? null, proc?.comm ?? null, proc?.exe ?? null, event.container?.cgroup ?? null, event.correlationId ?? null, jsonOrNull(event.args), jsonOrNull(event.proc), jsonOrNull(event.container), jsonOrNull(event.net));
    }
    appendVerdict(eventId, verdict) {
        if (!this.insertVerdictStmt)
            return;
        const f = verdict.final;
        this.insertVerdictStmt.run(eventId, this.now(), f.action, f.severity, f.judgeId, f.confidence, f.reason ?? null, jsonOrNull(verdict.sources));
    }
    /** Query events newest-first. Returns [] when the index is unavailable. */
    query(q = {}) {
        if (!this.db)
            return [];
        const where = [];
        const params = [];
        const eq = (col, val) => {
            if (val !== undefined) {
                where.push(`${col} = ?`);
                params.push(val);
            }
        };
        eq("session_key", q.sessionKey);
        eq("run_id", q.runId);
        eq("pid", q.pid);
        eq("ppid", q.ppid);
        eq("syscall", q.syscall);
        eq("source", q.source);
        if (q.since !== undefined) {
            where.push("ts >= ?");
            params.push(q.since);
        }
        if (q.until !== undefined) {
            where.push("ts <= ?");
            params.push(q.until);
        }
        const limit = q.limit && q.limit > 0 ? Math.floor(q.limit) : 500;
        const sql = `SELECT * FROM events` +
            (where.length ? ` WHERE ${where.join(" AND ")}` : "") +
            ` ORDER BY ts DESC, rowid DESC LIMIT ${limit}`;
        const rows = this.db.prepare(sql).all(...params);
        return rows.map(toEventRow);
    }
    close() {
        if (this.db) {
            try {
                this.db.close();
            }
            catch {
                // ignore
            }
            this.db = null;
        }
    }
}
function jsonOrNull(v) {
    if (v === undefined || v === null)
        return null;
    try {
        return JSON.stringify(v);
    }
    catch {
        return null;
    }
}
function parseJson(v) {
    if (typeof v !== "string" || !v)
        return null;
    try {
        const parsed = JSON.parse(v);
        return parsed && typeof parsed === "object" ? parsed : null;
    }
    catch {
        return null;
    }
}
function toEventRow(r) {
    const numOrNull = (v) => (typeof v === "number" ? v : null);
    const strOrNull = (v) => (typeof v === "string" ? v : null);
    return {
        id: String(r.id),
        ts: Number(r.ts),
        source: String(r.source),
        syscall: String(r.syscall),
        pid: Number(r.pid),
        ppid: numOrNull(r.ppid),
        uid: numOrNull(r.uid),
        gid: numOrNull(r.gid),
        sessionKey: strOrNull(r.session_key),
        runId: strOrNull(r.run_id),
        toolName: strOrNull(r.tool_name),
        comm: strOrNull(r.comm),
        exe: strOrNull(r.exe),
        cgroup: strOrNull(r.cgroup),
        correlationId: strOrNull(r.correlation_id),
        args: parseJson(r.args_json) ?? {},
        proc: parseJson(r.proc_json),
        container: parseJson(r.container_json),
        net: parseJson(r.net_json),
    };
}
