import { describe, expect, it } from "vitest";
import { detectLsmSupport } from "../probes/lsm/platform.js";

describe("detectLsmSupport", () => {
  it("rejects non-Linux platforms early", () => {
    expect(detectLsmSupport("darwin").supported).toBe(false);
    expect(detectLsmSupport("win32").supported).toBe(false);
  });

  it("on linux returns a structured result (may be unsupported in test env)", () => {
    const r = detectLsmSupport("linux");
    expect(r.platform).toBe("linux");
    expect(typeof r.kernel).toBe("string");
    if (!r.supported) {
      expect(typeof r.reason).toBe("string");
    }
  });
});
