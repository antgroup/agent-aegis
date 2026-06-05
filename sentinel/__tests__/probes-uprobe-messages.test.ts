import { describe, expect, it } from "vitest";
import { parseUprobeMessage } from "../probes/uprobe/messages.js";

describe("parseUprobeMessage", () => {
  it("returns null for empty / blank lines", () => {
    expect(parseUprobeMessage("")).toBeNull();
    expect(parseUprobeMessage("   ")).toBeNull();
  });

  it("returns null for invalid JSON", () => {
    expect(parseUprobeMessage("not json")).toBeNull();
    expect(parseUprobeMessage("{")).toBeNull();
  });

  it("returns null for unknown kinds", () => {
    expect(parseUprobeMessage('{"kind":"xyz"}')).toBeNull();
  });

  it("parses ready messages with string array", () => {
    expect(
      parseUprobeMessage('{"kind":"ready","probes":["execve","openat","SSL_write"]}'),
    ).toEqual({
      kind: "ready",
      probes: ["execve", "openat", "SSL_write"],
    });
    expect(parseUprobeMessage('{"kind":"ready","probes":[1]}')).toBeNull();
  });

  it("parses syscall messages with ppid/comm/path", () => {
    const out = parseUprobeMessage(
      '{"kind":"syscall","syscall":"execve","pid":1234,"ppid":1,"ts":1000,"path":"/bin/cat","comm":"bash","argv":["/bin/cat","/etc/shadow"]}',
    );
    expect(out).toEqual({
      kind: "syscall",
      syscall: "execve",
      pid: 1234,
      ppid: 1,
      ts: 1000,
      path: "/bin/cat",
      comm: "bash",
      argv: ["/bin/cat", "/etc/shadow"],
    });
  });

  it("parses SSL_write with preview + size in extra", () => {
    const out = parseUprobeMessage(
      '{"kind":"syscall","syscall":"SSL_write","pid":1,"ts":1,"preview":"GET /","extra":{"size":5}}',
    );
    expect(out).not.toBeNull();
    if (out && out.kind === "syscall") {
      expect(out.syscall).toBe("SSL_write");
      expect(out.preview).toBe("GET /");
      expect(out.extra).toEqual({ size: 5 });
    }
  });

  it("defaults pid/ts when missing on syscall", () => {
    const out = parseUprobeMessage('{"kind":"syscall","syscall":"openat"}');
    expect(out).not.toBeNull();
    if (out && out.kind === "syscall") {
      expect(out.pid).toBe(0);
      expect(typeof out.ts).toBe("number");
    }
  });

  it("rejects syscall messages without a syscall name", () => {
    expect(parseUprobeMessage('{"kind":"syscall","pid":1}')).toBeNull();
  });

  it("parses log messages with valid levels", () => {
    expect(parseUprobeMessage('{"kind":"log","level":"warn","message":"hi"}')).toEqual({
      kind: "log",
      level: "warn",
      message: "hi",
    });
    expect(parseUprobeMessage('{"kind":"log","level":"trace","message":"x"}')).toBeNull();
  });

  it("drops malformed argv arrays on syscall", () => {
    const out = parseUprobeMessage(
      '{"kind":"syscall","syscall":"execve","argv":["ok",1]}',
    );
    expect(out).not.toBeNull();
    if (out && out.kind === "syscall") {
      expect(out.argv).toBeUndefined();
    }
  });
});
