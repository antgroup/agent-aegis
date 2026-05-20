import { describe, expect, it } from "vitest";
import { createProbeEvent } from "../channel/event.js";
import { createNativeJudge } from "../judges/native.js";

describe("native judge — judgeKernelEscape slot", () => {
  it("blocks execve launched from /tmp/", async () => {
    const judge = createNativeJudge();
    const v = await judge.judge(
      createProbeEvent({
        source: "ebpf",
        syscall: "execve",
        pid: 200,
        args: { path: "/tmp/payload.sh" },
      }),
    );
    expect(v?.action).toBe("block");
    expect(v?.judgeId).toBe("native:kernel-escape");
    expect(v?.severity).toBe("high");
  });

  it("blocks execve from /dev/shm/ and /var/tmp/", async () => {
    const judge = createNativeJudge();
    expect(
      (await judge.judge(
        createProbeEvent({ source: "ebpf", syscall: "execve", pid: 1, args: { argv: ["/dev/shm/x"] } }),
      ))?.action,
    ).toBe("block");
    expect(
      (await judge.judge(
        createProbeEvent({ source: "ebpf", syscall: "execve", pid: 1, args: { path: "/var/tmp/y" } }),
      ))?.action,
    ).toBe("block");
  });

  it("allows execve from system bin directories", async () => {
    const judge = createNativeJudge();
    expect(
      await judge.judge(
        createProbeEvent({ source: "ebpf", syscall: "execve", pid: 1, args: { path: "/usr/bin/ls" } }),
      ),
    ).toBeNull();
  });

  it("supports caller-supplied scratch patterns", async () => {
    const judge = createNativeJudge({ scratchDirPatterns: [/^\/staging\//] });
    const v = await judge.judge(
      createProbeEvent({ source: "ebpf", syscall: "execve", pid: 1, args: { path: "/staging/x" } }),
    );
    expect(v?.action).toBe("block");
    // /tmp must not fire when default patterns are overridden:
    expect(
      await judge.judge(
        createProbeEvent({ source: "ebpf", syscall: "execve", pid: 1, args: { path: "/tmp/x" } }),
      ),
    ).toBeNull();
  });
});

describe("native judge — judgeProcessTreeAnomaly slot", () => {
  it("abstains when no agentPids are known", async () => {
    const judge = createNativeJudge();
    const v = await judge.judge(
      createProbeEvent({
        source: "ebpf",
        syscall: "openat",
        pid: 999,
        args: { path: "/tmp/x" },
        meta: { ppid: 1 },
      }),
    );
    // /tmp doesn't match openat (kernel-escape is execve-only), and there
    // are no agentPids to compare against; expect abstention.
    expect(v).toBeNull();
  });

  it("flags observe when ppid is outside known agent tree", async () => {
    const judge = createNativeJudge({ agentPids: [12345] });
    const v = await judge.judge(
      createProbeEvent({
        source: "ebpf",
        syscall: "openat",
        pid: 999,
        args: { path: "/etc/hosts" },
        meta: { ppid: 50000 },
      }),
    );
    expect(v?.action).toBe("observe");
    expect(v?.judgeId).toBe("native:process-tree-anomaly");
  });

  it("allows when ppid matches an agent pid", async () => {
    const judge = createNativeJudge({ agentPids: [12345] });
    expect(
      await judge.judge(
        createProbeEvent({
          source: "ebpf",
          syscall: "openat",
          pid: 999,
          args: { path: "/etc/hosts" },
          meta: { ppid: 12345 },
        }),
      ),
    ).toBeNull();
  });

  it("getAgentPids callback takes precedence over agentPids", async () => {
    const judge = createNativeJudge({ agentPids: [12345], getAgentPids: () => [99999] });
    const v = await judge.judge(
      createProbeEvent({
        source: "ebpf",
        syscall: "openat",
        pid: 1,
        args: { path: "/etc/hosts" },
        meta: { ppid: 12345 },
      }),
    );
    expect(v?.action).toBe("observe");
  });
});

describe("native judge — kernel-escape takes precedence over process-anomaly", () => {
  it("blocks /tmp execve regardless of ppid", async () => {
    const judge = createNativeJudge({ agentPids: [12345] });
    const v = await judge.judge(
      createProbeEvent({
        source: "ebpf",
        syscall: "execve",
        pid: 1,
        args: { path: "/tmp/x" },
        meta: { ppid: 12345 },
      }),
    );
    expect(v?.action).toBe("block");
    expect(v?.judgeId).toBe("native:kernel-escape");
  });
});
