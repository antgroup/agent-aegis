import { describe, expect, it } from "vitest";
import type { Verdict } from "../channel/event.js";
import { aggregate, runJudges } from "../judges/aggregator.js";
import type { Judge } from "../judges/base.js";
import { createProbeEvent } from "../channel/event.js";

function v(partial: Partial<Verdict> & Pick<Verdict, "action">): Verdict {
  return {
    severity: "low",
    reason: "test",
    judgeId: "j",
    confidence: 1,
    ...partial,
  };
}

describe("aggregate / strictest", () => {
  it("returns abstain verdict when no inputs", () => {
    const out = aggregate([], "strictest");
    expect(out.final.action).toBe("allow");
    expect(out.final.judgeId).toBe("aggregator:abstain");
    expect(out.sources).toEqual([]);
  });

  it("picks block over observe over allow", () => {
    const out = aggregate(
      [v({ action: "allow", judgeId: "a" }), v({ action: "observe", judgeId: "b" }), v({ action: "block", judgeId: "c" })],
      "strictest",
    );
    expect(out.final.action).toBe("block");
    expect(out.final.judgeId).toBe("c");
    expect(out.sources).toHaveLength(3);
  });

  it("breaks action ties by severity", () => {
    const out = aggregate(
      [
        v({ action: "block", judgeId: "low", severity: "low" }),
        v({ action: "block", judgeId: "critical", severity: "critical" }),
      ],
      "strictest",
    );
    expect(out.final.judgeId).toBe("critical");
  });
});

describe("aggregate / weighted", () => {
  it("picks the action with highest summed confidence", () => {
    const out = aggregate(
      [
        v({ action: "allow", confidence: 0.4, judgeId: "a" }),
        v({ action: "allow", confidence: 0.5, judgeId: "b" }),
        v({ action: "block", confidence: 0.6, judgeId: "c" }),
      ],
      "weighted",
    );
    expect(out.final.action).toBe("allow");
    expect(out.final.judgeId).toContain("weighted");
  });

  it("breaks score ties in favor of the stricter action", () => {
    const out = aggregate(
      [
        v({ action: "allow", confidence: 1, judgeId: "a" }),
        v({ action: "block", confidence: 1, judgeId: "b" }),
      ],
      "weighted",
    );
    expect(out.final.action).toBe("block");
  });
});

describe("runJudges", () => {
  it("collects non-null verdicts and drops abstentions", async () => {
    const judges: Judge[] = [
      { id: "j1", judge: async () => v({ action: "observe", judgeId: "j1" }) },
      { id: "j2", judge: async () => null },
      { id: "j3", judge: async () => v({ action: "block", judgeId: "j3" }) },
    ];
    const ev = createProbeEvent({ source: "test", syscall: "x", pid: 0, args: {} });
    const errors: string[] = [];
    const out = await runJudges(judges, ev, (id, err) => {
      errors.push(`${id}:${String(err)}`);
    });
    expect(out.map((x) => x.judgeId).sort()).toEqual(["j1", "j3"]);
    expect(errors).toEqual([]);
  });

  it("converts thrown errors into abstentions and reports them", async () => {
    const judges: Judge[] = [
      {
        id: "boom",
        judge: async () => {
          throw new Error("kaboom");
        },
      },
      { id: "ok", judge: async () => v({ action: "allow", judgeId: "ok" }) },
    ];
    const ev = createProbeEvent({ source: "test", syscall: "x", pid: 0, args: {} });
    const errors: string[] = [];
    const out = await runJudges(judges, ev, (id, err) => {
      errors.push(`${id}:${String(err)}`);
    });
    expect(out.map((x) => x.judgeId)).toEqual(["ok"]);
    expect(errors).toHaveLength(1);
    expect(errors[0]).toContain("boom");
  });
});
