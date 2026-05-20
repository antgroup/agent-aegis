import { describe, expect, it } from "vitest";
import { parseAgentMessage } from "../probes/frida/messages.js";

describe("parseAgentMessage", () => {
  it("returns null for non-objects", () => {
    expect(parseAgentMessage(null)).toBeNull();
    expect(parseAgentMessage("hello")).toBeNull();
    expect(parseAgentMessage(42)).toBeNull();
  });

  it("returns null for unknown kinds", () => {
    expect(parseAgentMessage({ kind: "something-else" })).toBeNull();
  });

  it("parses a complete syscall message", () => {
    const out = parseAgentMessage({
      kind: "syscall",
      syscall: "execve",
      pid: 42,
      ts: 1234,
      argv: ["/bin/ls", "-la"],
      path: "/bin/ls",
    });
    expect(out).toEqual({
      kind: "syscall",
      syscall: "execve",
      pid: 42,
      ts: 1234,
      argv: ["/bin/ls", "-la"],
      path: "/bin/ls",
    });
  });

  it("fills timestamp when missing on syscall", () => {
    const out = parseAgentMessage({ kind: "syscall", syscall: "openat" });
    expect(out).not.toBeNull();
    expect(out!.kind).toBe("syscall");
    if (out!.kind === "syscall") {
      expect(typeof out.ts).toBe("number");
      expect(out.pid).toBe(0);
    }
  });

  it("rejects syscall messages without a syscall name", () => {
    expect(parseAgentMessage({ kind: "syscall", pid: 1 })).toBeNull();
  });

  it("drops malformed argv arrays on syscall", () => {
    const out = parseAgentMessage({
      kind: "syscall",
      syscall: "execve",
      argv: ["/bin/ls", 123],
    });
    expect(out).not.toBeNull();
    if (out && out.kind === "syscall") {
      expect(out.argv).toBeUndefined();
    }
  });

  it("parses log messages with valid levels only", () => {
    expect(parseAgentMessage({ kind: "log", level: "info", message: "hi" })).toEqual({
      kind: "log",
      level: "info",
      message: "hi",
    });
    expect(parseAgentMessage({ kind: "log", level: "trace", message: "x" })).toBeNull();
  });

  it("parses ready messages with string array", () => {
    expect(
      parseAgentMessage({ kind: "ready", hookedTargets: ["execve", "openat"] }),
    ).toEqual({ kind: "ready", hookedTargets: ["execve", "openat"] });
    expect(parseAgentMessage({ kind: "ready", hookedTargets: "execve" })).toBeNull();
    expect(parseAgentMessage({ kind: "ready", hookedTargets: ["execve", 1] })).toBeNull();
  });

  it("parses error and unsupported messages", () => {
    expect(parseAgentMessage({ kind: "error", where: "x", message: "y" })).toEqual({
      kind: "error",
      where: "x",
      message: "y",
    });
    expect(parseAgentMessage({ kind: "unsupported", platform: "win32" })).toEqual({
      kind: "unsupported",
      platform: "win32",
    });
  });
});
