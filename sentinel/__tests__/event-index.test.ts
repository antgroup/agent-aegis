import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { createProbeEvent } from "../channel/event.js";
import { SqliteEventIndex } from "../channel/event-index.js";

let baseDir: string;
let index: SqliteEventIndex;

beforeEach(() => {
  baseDir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-index-"));
  index = new SqliteEventIndex({ stateDir: baseDir, now: () => 5000 });
});

afterEach(() => {
  index.close();
  fs.rmSync(baseDir, { recursive: true, force: true });
});

function ev(over: Partial<Parameters<typeof createProbeEvent>[0]> = {}) {
  return createProbeEvent({
    source: "ebpf",
    syscall: "openat",
    pid: 100,
    args: {},
    ...over,
  });
}

describe("SqliteEventIndex", () => {
  it("is available on a modern Node (node:sqlite present)", () => {
    expect(index.available).toBe(true);
    expect(index.unavailableReason).toBeNull();
    // the db file is created under probe-events/
    expect(fs.existsSync(path.join(baseDir, "probe-events", "index.db"))).toBe(true);
  });

  it("indexes events and queries them newest-first", () => {
    index.appendEvent(ev({ id: "a", timestamp: 1000, syscall: "execve" }));
    index.appendEvent(ev({ id: "b", timestamp: 3000, syscall: "openat" }));
    index.appendEvent(ev({ id: "c", timestamp: 2000, syscall: "connect" }));
    const rows = index.query();
    expect(rows.map((r) => r.id)).toEqual(["b", "c", "a"]); // ts DESC
  });

  it("filters by session / run / pid / syscall / time range", () => {
    index.appendEvent(ev({ id: "s1", timestamp: 1000, pid: 10, sessionKey: "sess-1", syscall: "openat" }));
    index.appendEvent(ev({ id: "s2", timestamp: 2000, pid: 20, sessionKey: "sess-2", runId: "run-x", syscall: "connect" }));
    index.appendEvent(ev({ id: "s3", timestamp: 3000, pid: 10, sessionKey: "sess-1", syscall: "execve" }));

    expect(index.query({ sessionKey: "sess-1" }).map((r) => r.id)).toEqual(["s3", "s1"]);
    expect(index.query({ pid: 20 }).map((r) => r.id)).toEqual(["s2"]);
    expect(index.query({ runId: "run-x" }).map((r) => r.id)).toEqual(["s2"]);
    expect(index.query({ syscall: "execve" }).map((r) => r.id)).toEqual(["s3"]);
    expect(index.query({ since: 1500, until: 2500 }).map((r) => r.id)).toEqual(["s2"]);
    expect(index.query({ limit: 1 }).map((r) => r.id)).toEqual(["s3"]); // newest, capped
  });

  it("round-trips proc / container / net through JSON columns + index helpers", () => {
    index.appendEvent(
      ev({
        id: "rich",
        timestamp: 1000,
        syscall: "connect",
        pid: 4242,
        proc: { ppid: 7, uid: 1000, gid: 1000, comm: "curl", exe: "/usr/bin/curl", ancestors: [7, 1] },
        container: { cgroup: "/agent.service" },
        net: { proto: "tcp", daddr: "1.2.3.4", dport: 443 },
        correlationId: "corr-1",
      }),
    );
    const [row] = index.query({ pid: 4242 });
    expect(row.ppid).toBe(7); // promoted indexed column
    expect(row.uid).toBe(1000);
    expect(row.comm).toBe("curl");
    expect(row.exe).toBe("/usr/bin/curl");
    expect(row.cgroup).toBe("/agent.service");
    expect(row.correlationId).toBe("corr-1");
    expect(row.proc).toMatchObject({ ancestors: [7, 1] });
    expect(row.net).toEqual({ proto: "tcp", daddr: "1.2.3.4", dport: 443 });
    expect(row.container).toEqual({ cgroup: "/agent.service" });
  });

  it("stores verdicts without throwing and re-inserts events idempotently", () => {
    const e = ev({ id: "dup", timestamp: 1000 });
    index.appendEvent(e);
    index.appendEvent(e); // INSERT OR REPLACE — no PK error, still one row
    index.appendVerdict("dup", {
      final: { action: "block", severity: "high", reason: "nope", judgeId: "native", confidence: 0.9 },
      sources: [{ action: "block", severity: "high", reason: "nope", judgeId: "native", confidence: 0.9 }],
    });
    expect(index.query({}).filter((r) => r.id === "dup")).toHaveLength(1);
  });
});
