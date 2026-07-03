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

describe("parseEbpfMessage — lifecycle messages (M10 P1.2)", () => {
  it("parses fork lifecycle messages", () => {
    const line = JSON.stringify({
      kind: "lifecycle",
      event: "fork",
      pid: 100,
      ppid: 1,
      ts: 5000,
      comm: "bash",
      childPid: 200,
      proc: { ppid: 1, uid: 0 },
    });
    const out = parseEbpfMessage(line);
    expect(out).not.toBeNull();
    if (out && out.kind === "lifecycle") {
      expect(out.event).toBe("fork");
      expect(out.pid).toBe(100);
      expect(out.ppid).toBe(1);
      expect(out.ts).toBe(5000);
      expect(out.comm).toBe("bash");
      expect(out.childPid).toBe(200);
      expect(out.proc).toEqual({ ppid: 1, uid: 0 });
    }
  });

  it("parses exec lifecycle messages with argv", () => {
    const line = JSON.stringify({
      kind: "lifecycle",
      event: "exec",
      pid: 200,
      ppid: 100,
      ts: 5001,
      comm: "cat",
      path: "/bin/cat",
      argv: ["cat", "/etc/shadow"],
    });
    const out = parseEbpfMessage(line);
    expect(out).not.toBeNull();
    if (out && out.kind === "lifecycle") {
      expect(out.event).toBe("exec");
      expect(out.pid).toBe(200);
      expect(out.path).toBe("/bin/cat");
      expect(out.argv).toEqual(["cat", "/etc/shadow"]);
      expect(out.exitCode).toBeUndefined();
    }
  });

  it("parses exit lifecycle messages with exitCode", () => {
    const line = JSON.stringify({
      kind: "lifecycle",
      event: "exit",
      pid: 200,
      ppid: 100,
      ts: 5002,
      comm: "cat",
      exitCode: 0,
    });
    const out = parseEbpfMessage(line);
    expect(out).not.toBeNull();
    if (out && out.kind === "lifecycle") {
      expect(out.event).toBe("exit");
      expect(out.pid).toBe(200);
      expect(out.exitCode).toBe(0);
      expect(out.childPid).toBeUndefined();
    }
  });

  it("returns null for lifecycle with invalid event type", () => {
    expect(parseEbpfMessage('{"kind":"lifecycle","event":"unknown","pid":1,"ts":1}')).toBeNull();
  });

  it("defaults pid/ts when missing on lifecycle", () => {
    const out = parseEbpfMessage('{"kind":"lifecycle","event":"fork"}');
    expect(out).not.toBeNull();
    if (out && out.kind === "lifecycle") {
      expect(out.pid).toBe(0);
      expect(typeof out.ts).toBe("number");
    }
  });

  it("ignores unknown fields on lifecycle messages", () => {
    const out = parseEbpfMessage(
      '{"kind":"lifecycle","event":"exit","pid":1,"ts":1,"exitCode":2,"bogus":true}',
    );
    expect(out).not.toBeNull();
    if (out && out.kind === "lifecycle") {
      expect(out.exitCode).toBe(2);
      // @ts-expect-error — bogus field should not appear on the typed object
      expect((out as Record<string, unknown>).bogus).toBeUndefined();
    }
  });
});
