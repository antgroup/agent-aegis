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
