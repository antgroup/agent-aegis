import { describe, expect, it } from "vitest";
import { _internalReadNativeJudgeConfig } from "../../index.js";
import { createProbeEvent } from "../channel/event.js";
import { createNativeJudge } from "../judges/native.js";

describe("_internalReadNativeJudgeConfig", () => {
  it("returns empty object when nativeJudge is missing", () => {
    expect(_internalReadNativeJudgeConfig({})).toEqual({});
  });

  it("translates sensitivePaths into substring-with-boundary RegExps", () => {
    const out = _internalReadNativeJudgeConfig({
      nativeJudge: { sensitivePaths: ["/etc/shadow", "/Users/me/.ssh/id_rsa"] },
    });
    expect(out.sensitivePathPatterns).toHaveLength(2);
    // Substring match anywhere in haystack:
    expect(out.sensitivePathPatterns![0].test("cat /etc/shadow")).toBe(true);
    expect(out.sensitivePathPatterns![0].test("/etc/shadow")).toBe(true);
    // Boundary prevents .bak / .backup tail matches:
    expect(out.sensitivePathPatterns![0].test("/etc/shadowbak")).toBe(false);
    // RegExp metacharacters in the input get escaped:
    const meta = _internalReadNativeJudgeConfig({
      nativeJudge: { sensitivePaths: ["/etc/foo.bar"] },
    });
    expect(meta.sensitivePathPatterns![0].test("/etc/fooXbar")).toBe(false);
    expect(meta.sensitivePathPatterns![0].test("/etc/foo.bar")).toBe(true);
  });

  it("translates scratchDirs into anchored RegExps (must start with the prefix)", () => {
    const out = _internalReadNativeJudgeConfig({
      nativeJudge: { scratchDirs: ["/tmp/", "/dev/shm/"] },
    });
    expect(out.scratchDirPatterns).toHaveLength(2);
    expect(out.scratchDirPatterns![0].test("/tmp/x")).toBe(true);
    expect(out.scratchDirPatterns![0].test("/var/tmp/x")).toBe(false); // anchored
    expect(out.scratchDirPatterns![1].test("/dev/shm/payload")).toBe(true);
  });

  it("ignores non-string / empty entries instead of crashing", () => {
    const out = _internalReadNativeJudgeConfig({
      nativeJudge: {
        sensitivePaths: ["/etc/shadow", "", 42, null, "/var/db/secret"],
      },
    });
    expect(out.sensitivePathPatterns).toHaveLength(2);
  });

  it("plumbs translated patterns through createNativeJudge for a real verdict", async () => {
    const cfg = _internalReadNativeJudgeConfig({
      nativeJudge: { sensitivePaths: ["/Users/me/.ssh/id_rsa"] },
    });
    const judge = createNativeJudge({
      sensitivePathPatterns: cfg.sensitivePathPatterns,
    });
    const v = await judge.judge(
      createProbeEvent({
        source: "ebpf",
        syscall: "openat",
        pid: 1234,
        args: { path: "/Users/me/.ssh/id_rsa" },
      }),
    );
    expect(v?.action).toBe("block");
    expect(v?.judgeId).toBe("native:sensitive-path");
  });
});
