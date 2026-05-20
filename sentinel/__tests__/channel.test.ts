import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { ProbeEventBus } from "../channel/bus.js";
import { createProbeEvent } from "../channel/event.js";
import { EVENT_SCHEMA_VERSION } from "../channel/schema.js";
import { ProbeEventStore } from "../channel/store.js";

describe("createProbeEvent", () => {
  it("stamps schema, id, and timestamp", () => {
    const ev = createProbeEvent({
      source: "test",
      syscall: "execve",
      pid: 1234,
      args: { argv: ["/bin/ls"] },
    });
    expect(ev.schema).toBe(EVENT_SCHEMA_VERSION);
    expect(ev.id).toMatch(/[0-9a-f-]+/);
    expect(ev.timestamp).toBeGreaterThan(0);
    expect(ev.pid).toBe(1234);
  });

  it("preserves caller-supplied id and timestamp", () => {
    const ev = createProbeEvent({
      id: "fixed-id",
      timestamp: 42,
      source: "test",
      syscall: "openat",
      pid: 0,
      args: {},
    });
    expect(ev.id).toBe("fixed-id");
    expect(ev.timestamp).toBe(42);
  });
});

describe("ProbeEventBus", () => {
  it("delivers events to all subscribers asynchronously", async () => {
    const bus = new ProbeEventBus();
    const seen: string[] = [];
    bus.subscribe((e) => {
      seen.push(`a:${e.id}`);
    });
    bus.subscribe((e) => {
      seen.push(`b:${e.id}`);
    });
    bus.publish(createProbeEvent({ source: "test", syscall: "x", pid: 0, args: {}, id: "1" }));
    await flush();
    expect(seen.sort()).toEqual(["a:1", "b:1"]);
  });

  it("isolates subscriber errors via onError", async () => {
    const errors: string[] = [];
    const bus = new ProbeEventBus({
      onError: (err) => errors.push(String(err)),
    });
    bus.subscribe(() => {
      throw new Error("bad subscriber");
    });
    const ok: string[] = [];
    bus.subscribe((e) => ok.push(e.id));
    bus.publish(createProbeEvent({ source: "test", syscall: "x", pid: 0, args: {}, id: "2" }));
    await flush();
    expect(errors).toHaveLength(1);
    expect(ok).toEqual(["2"]);
  });

  it("unsubscribe stops delivery", async () => {
    const bus = new ProbeEventBus();
    const seen: string[] = [];
    const unsub = bus.subscribe((e) => seen.push(e.id));
    unsub();
    bus.publish(createProbeEvent({ source: "test", syscall: "x", pid: 0, args: {}, id: "3" }));
    await flush();
    expect(seen).toEqual([]);
    expect(bus.size()).toBe(0);
  });
});

describe("ProbeEventStore", () => {
  let dir: string;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), "sentinel-store-"));
  });

  afterEach(() => {
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it("writes events as JSONL and creates the subdirectory", async () => {
    const store = new ProbeEventStore({ stateDir: dir });
    const ev = createProbeEvent({ source: "test", syscall: "x", pid: 0, args: {}, id: "evt-1" });
    store.appendEvent(ev);
    await store.close();

    const file = store.currentFile();
    expect(fs.existsSync(file)).toBe(true);
    const lines = fs.readFileSync(file, "utf8").trim().split("\n");
    expect(lines).toHaveLength(1);
    const parsed = JSON.parse(lines[0]);
    expect(parsed.kind).toBe("event");
    expect(parsed.id).toBe("evt-1");
  });

  it("rotates files when UTC date changes", async () => {
    let date = new Date(Date.UTC(2026, 4, 15));
    const store = new ProbeEventStore({ stateDir: dir, now: () => date });
    store.appendEvent(createProbeEvent({ source: "test", syscall: "x", pid: 0, args: {}, id: "a" }));
    date = new Date(Date.UTC(2026, 4, 16));
    store.appendEvent(createProbeEvent({ source: "test", syscall: "x", pid: 0, args: {}, id: "b" }));
    await store.close();

    const files = fs
      .readdirSync(path.join(dir, "probe-events"))
      .filter((f) => f.endsWith(".jsonl"))
      .sort();
    expect(files).toEqual(["events-2026-05-15.jsonl", "events-2026-05-16.jsonl"]);
  });
});

function flush(): Promise<void> {
  return new Promise((resolve) => setImmediate(resolve));
}
