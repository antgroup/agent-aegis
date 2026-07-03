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

  it("observe mode downgrades the block verdict to observe (detect-but-don't-block)", async () => {
    const judge = createNativeJudge({ mode: "observe" });
    const ev = createProbeEvent({
      source: "ebpf",
      syscall: "openat",
      pid: 4242,
      args: { path: "/etc/shadow" },
    });
    const verdict = await judge.judge(ev);
    expect(verdict).not.toBeNull();
    // Still detected, with full severity/reason/judgeId for the audit + WebUI…
    expect(verdict!.judgeId).toBe("native:sensitive-path");
    expect(verdict!.severity).toBe("critical");
    expect(verdict!.reason).toMatch(/sensitive path/);
    // …but downgraded so the hook never intercepts.
    expect(verdict!.action).toBe("observe");
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

  // --- M11: attribution-path process tree anomaly ---

  it("M11: external attribution triggers process-tree-anomaly at medium severity", async () => {
    const judge = createNativeJudge();
    const ev = createProbeEvent({
      source: "ebpf",
      syscall: "openat",
      pid: 9999,
      args: { path: "/var/log/syslog" },
      meta: { attribution: "external" },
    });
    const v = await judge.judge(ev);
    expect(v).not.toBeNull();
    expect(v!.action).toBe("observe");
    expect(v!.severity).toBe("medium");
    expect(v!.judgeId).toBe("native:process-tree-anomaly");
    expect(v!.confidence).toBe(0.8);
    expect(v!.reason).toMatch(/attribution=external/);
  });

  it("M11: agent attribution skips process-tree-anomaly", async () => {
    const judge = createNativeJudge();
    const ev = createProbeEvent({
      source: "ebpf",
      syscall: "openat",
      pid: 1000,
      args: { path: "/tmp/file" },
      meta: { attribution: "agent" },
    });
    expect(await judge.judge(ev)).toBeNull();
  });

  it("M11: descendant attribution skips process-tree-anomaly", async () => {
    const judge = createNativeJudge();
    const ev = createProbeEvent({
      source: "ebpf",
      syscall: "openat",
      pid: 2000,
      args: { path: "/tmp/file" },
      meta: { attribution: "descendant" },
    });
    expect(await judge.judge(ev)).toBeNull();
  });

  it("M11: fallback to ppid heuristic when no attribution present", async () => {
    const judge = createNativeJudge({ agentPids: [1000] });
    // No meta.attribution — falls back to ppid check.
    const ev = createProbeEvent({
      source: "ebpf",
      syscall: "openat",
      pid: 2000,
      args: { path: "/tmp/file" },
      meta: { ppid: 5000 }, // not in agentPids
    });
    const v = await judge.judge(ev);
    expect(v).not.toBeNull();
    expect(v!.severity).toBe("low"); // lower confidence than attribution path
    expect(v!.judgeId).toBe("native:process-tree-anomaly");
  });
});
