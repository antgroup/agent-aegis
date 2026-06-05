import { describe, expect, it } from "vitest";
import { createProbeEvent } from "../channel/event.js";
import { createNativeJudge } from "../judges/native.js";

describe("createNativeJudge", () => {
  it("abstains on tool_call (handled by L1 bridge)", async () => {
    const judge = createNativeJudge();
    const ev = createProbeEvent({
      source: "l1-hook",
      syscall: "tool_call",
      pid: 0,
      args: { toolName: "terminal" },
    });
    expect(await judge.judge(ev)).toBeNull();
  });

  it("abstains when execve argv is missing or malformed", async () => {
    const judge = createNativeJudge();
    const ev = createProbeEvent({
      source: "uprobe",
      syscall: "execve",
      pid: 100,
      args: { not_argv: "x" },
    });
    expect(await judge.judge(ev)).toBeNull();
  });

  it("blocks execve whose argv touches /etc/shadow", async () => {
    const judge = createNativeJudge();
    const ev = createProbeEvent({
      source: "uprobe",
      syscall: "execve",
      pid: 100,
      args: { argv: ["/bin/cat", "/etc/shadow"] },
    });
    const verdict = await judge.judge(ev);
    expect(verdict).not.toBeNull();
    expect(verdict!.action).toBe("block");
    expect(verdict!.severity).toBe("critical");
    expect(verdict!.judgeId).toBe("native:sensitive-path");
    expect(verdict!.reason).toMatch(/sensitive path/);
    expect(verdict!.sideEffects?.[0]).toMatchObject({ kind: "log", level: "error" });
  });

  it("blocks openat whose path is sensitive (M5 real-env scenario)", async () => {
    const judge = createNativeJudge();
    const ev = createProbeEvent({
      source: "ebpf",
      syscall: "openat",
      pid: 21586,
      args: { path: "/etc/shadow" },
      meta: { ppid: 21552, comm: "cat" },
    });
    const verdict = await judge.judge(ev);
    expect(verdict?.action).toBe("block");
    expect(verdict?.judgeId).toBe("native:sensitive-path");
    expect(verdict?.severity).toBe("critical");
  });

  it("allows a normal execve", async () => {
    const judge = createNativeJudge();
    const ev = createProbeEvent({
      source: "ebpf",
      syscall: "execve",
      pid: 200,
      args: { argv: ["/bin/ls", "-la", "/tmp"] },
    });
    expect(await judge.judge(ev)).toBeNull();
  });

  it("supports caller-supplied sensitive patterns", async () => {
    const judge = createNativeJudge({
      sensitivePathPatterns: [/\/srv\/secrets\//],
    });
    const blocked = await judge.judge(
      createProbeEvent({
        source: "uprobe",
        syscall: "execve",
        pid: 300,
        args: { argv: ["/usr/bin/python", "-c", "open('/srv/secrets/db.key')"] },
      }),
    );
    expect(blocked?.action).toBe("block");
  });
});
