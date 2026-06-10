import { describe, expect, it } from "vitest";
import { parseEbpfMessage } from "../probes/ebpf/messages.js";

describe("parseEbpfMessage", () => {
  it("returns null for empty / blank lines", () => {
    expect(parseEbpfMessage("")).toBeNull();
    expect(parseEbpfMessage("   ")).toBeNull();
  });

  it("returns null for invalid JSON", () => {
    expect(parseEbpfMessage("not json")).toBeNull();
    expect(parseEbpfMessage("{")).toBeNull();
  });

  it("returns null for unknown kinds", () => {
    expect(parseEbpfMessage('{"kind":"xyz"}')).toBeNull();
  });

  it("parses ready messages with string array", () => {
    expect(parseEbpfMessage('{"kind":"ready","probes":["execve","openat"]}')).toEqual({
      kind: "ready",
      probes: ["execve", "openat"],
    });
    expect(parseEbpfMessage('{"kind":"ready","probes":[1]}')).toBeNull();
  });

  it("parses syscall messages with ppid/comm/path", () => {
    const out = parseEbpfMessage(
      '{"kind":"syscall","syscall":"execve","pid":1234,"ppid":1,"ts":1000,"path":"/bin/cat","comm":"bash"}',
    );
    expect(out).toEqual({
      kind: "syscall",
      syscall: "execve",
      pid: 1234,
      ppid: 1,
      ts: 1000,
      path: "/bin/cat",
      comm: "bash",
    });
  });

  it("defaults pid/ts when missing on syscall", () => {
    const out = parseEbpfMessage('{"kind":"syscall","syscall":"openat"}');
    expect(out).not.toBeNull();
    if (out && out.kind === "syscall") {
      expect(out.pid).toBe(0);
      expect(typeof out.ts).toBe("number");
    }
  });

  it("rejects syscall messages without a syscall name", () => {
    expect(parseEbpfMessage('{"kind":"syscall","pid":1}')).toBeNull();
  });

  it("parses log messages with valid levels", () => {
    expect(parseEbpfMessage('{"kind":"log","level":"warn","message":"hi"}')).toEqual({
      kind: "log",
      level: "warn",
      message: "hi",
    });
    expect(parseEbpfMessage('{"kind":"log","level":"trace","message":"x"}')).toBeNull();
  });
});

describe("parseEbpfMessage — v2 enrichment (proc/container/net)", () => {
  it("parses proc / container / net objects", () => {
    const line = JSON.stringify({
      kind: "syscall",
      syscall: "connect",
      pid: 4242,
      ts: 2000,
      proc: {
        ppid: 7,
        pgid: 4242,
        sid: 4000,
        uid: 1000,
        gid: 1000,
        exe: "/usr/bin/curl",
        cwd: "/home/admin",
        cmdline: ["curl", "http://x"],
        startTime: 9999,
        ancestors: [7, 1],
      },
      container: { cgroup: "/system.slice/agent.service" },
      net: { family: "inet", proto: "tcp", daddr: "1.2.3.4", dport: 443 },
    });
    const out = parseEbpfMessage(line);
    expect(out).not.toBeNull();
    if (out && out.kind === "syscall") {
      expect(out.proc).toEqual({
        ppid: 7,
        pgid: 4242,
        sid: 4000,
        uid: 1000,
        gid: 1000,
        exe: "/usr/bin/curl",
        cwd: "/home/admin",
        cmdline: ["curl", "http://x"],
        startTime: 9999,
        ancestors: [7, 1],
      });
      expect(out.container).toEqual({ cgroup: "/system.slice/agent.service" });
      expect(out.net).toEqual({ family: "inet", proto: "tcp", daddr: "1.2.3.4", dport: 443 });
    }
  });

  it("drops malformed enrichment fields but keeps the good ones", () => {
    const line = JSON.stringify({
      kind: "syscall",
      syscall: "openat",
      pid: 1,
      ts: 1,
      proc: { ppid: "nope", uid: 0, cmdline: ["ok", 5], ancestors: [1, "x"] },
      container: "not-an-object",
      net: { dport: "443", family: "inet6" },
    });
    const out = parseEbpfMessage(line);
    expect(out).not.toBeNull();
    if (out && out.kind === "syscall") {
      expect(out.proc).toEqual({ uid: 0 }); // bad ppid/cmdline/ancestors dropped
      expect(out.container).toBeUndefined(); // non-object dropped
      expect(out.net).toEqual({ family: "inet6" }); // bad dport dropped
    }
  });

  it("omits proc/container/net when absent", () => {
    const out = parseEbpfMessage('{"kind":"syscall","syscall":"execve","pid":1,"ts":1}');
    expect(out).not.toBeNull();
    if (out && out.kind === "syscall") {
      expect(out.proc).toBeUndefined();
      expect(out.container).toBeUndefined();
      expect(out.net).toBeUndefined();
    }
  });
});
