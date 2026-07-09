import { describe, expect, it } from "vitest";
import type { Verdict } from "../channel/event.js";
import { aggregate, runJudges } from "../judges/aggregator.js";
import type { Judge } from "../judges/base.js";
import { createProbeEvent } from "../channel/event.js";
import { ResponsePolicyEngine } from "../response/policy.js";
import { sampleDataset, summarizeDataset } from "../bench/agenthazard/adapter.js";
import type { AgentHazardInstance } from "../bench/agenthazard/types.js";

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

describe("ResponsePolicyEngine", () => {
  const capabilities = {
    canBlockToolCall: true,
    canTerminateProcess: false,
    platform: "linux" as const,
  };

  it("is fail-open when disabled", () => {
    const engine = new ResponsePolicyEngine({ capabilities });
    const event = createProbeEvent({ source: "test", syscall: "openat", pid: 1, args: {} });
    const verdict = aggregate([v({ action: "observe", severity: "medium" })], "strictest");

    expect(engine.apply(event, verdict)).toBe(verdict);
  });

  it("does not add response plans to low-risk allow verdicts", () => {
    const engine = new ResponsePolicyEngine({
      capabilities,
      config: { enabled: true, mode: "observe" },
    });
    const event = createProbeEvent({ source: "test", syscall: "openat", pid: 1, args: {} });
    const verdict = aggregate(
      [v({ action: "allow", severity: "low", confidence: 0.2 })],
      "strictest",
    );

    expect(engine.apply(event, verdict)).toBe(verdict);
  });

  it("alerts in observe mode without promoting to block", () => {
    const engine = new ResponsePolicyEngine({
      capabilities,
      config: { enabled: true, mode: "observe" },
    });
    const event = createProbeEvent({
      source: "test",
      syscall: "connect",
      pid: 10,
      args: {},
      meta: { attribution: "descendant" },
    });
    const verdict = aggregate(
      [v({ action: "observe", severity: "high", confidence: 0.9, reason: "risky" })],
      "strictest",
    );

    const out = engine.apply(event, verdict);

    expect(out.final.action).toBe("observe");
    expect(out.final.sideEffects).toContainEqual(
      expect.objectContaining({ kind: "response_plan", applied: "alert", mode: "observe" }),
    );
    expect(out.final.sideEffects).toContainEqual(
      expect.objectContaining({ kind: "notify_user", message: "risky" }),
    );
  });

  it("keeps block verdicts blocked in enforce mode and records the plan", () => {
    const engine = new ResponsePolicyEngine({
      capabilities,
      config: { enabled: true, mode: "enforce" },
    });
    const event = createProbeEvent({
      source: "test",
      syscall: "execve",
      pid: 10,
      args: {},
      meta: { attribution: "descendant" },
    });
    const verdict = aggregate(
      [v({ action: "block", severity: "high", confidence: 0.9 })],
      "strictest",
    );

    const out = engine.apply(event, verdict);

    expect(out.final.action).toBe("block");
    expect(out.final.sideEffects).toContainEqual(
      expect.objectContaining({ kind: "response_plan", applied: "block", mode: "enforce" }),
    );
  });

  it("only plans process termination when explicitly allowed and attribution is safe to act on", () => {
    const engine = new ResponsePolicyEngine({
      capabilities: { ...capabilities, canTerminateProcess: true },
      config: { enabled: true, mode: "enforce", allowKill: true },
    });
    const verdict = aggregate(
      [v({ action: "block", severity: "critical", confidence: 1 })],
      "strictest",
    );
    const descendantEvent = createProbeEvent({
      source: "test",
      syscall: "execve",
      pid: 123,
      args: {},
      meta: { attribution: "descendant" },
    });
    const externalEvent = createProbeEvent({
      source: "test",
      syscall: "execve",
      pid: 456,
      args: {},
      meta: { attribution: "external" },
    });

    const descendant = engine.apply(descendantEvent, verdict);
    const external = engine.apply(externalEvent, verdict);

    expect(descendant.final.sideEffects).toContainEqual(
      expect.objectContaining({ kind: "response_plan", applied: "kill" }),
    );
    expect(descendant.final.sideEffects).toContainEqual(
      expect.objectContaining({ kind: "terminate_process", pid: 123 }),
    );
    expect(external.final.sideEffects).toContainEqual(
      expect.objectContaining({ kind: "response_plan", applied: "block" }),
    );
    expect(external.final.sideEffects).not.toContainEqual(
      expect.objectContaining({ kind: "terminate_process" }),
    );
  });
});

describe("AgentHazard Phase 0 adapter", () => {
  const dataset: AgentHazardInstance[] = [
    hz(1, "Data_Exfiltration", "Direct"),
    hz(2, "Data_Exfiltration", "Recursive_Salami_Slicing"),
    hz(3, "Data_Exfiltration", "Security_Audit_Gaslighting"),
    hz(4, "Data_Exfiltration", "Encoded_Payload_Smuggling"),
    hz(5, "System_RCE", "Direct"),
    hz(6, "System_RCE", "Recursive_Salami_Slicing"),
    hz(7, "System_RCE", "Security_Audit_Gaslighting"),
    hz(8, "System_RCE", "Encoded_Payload_Smuggling"),
  ];

  it("samples deterministically by category and jailbreak method strata", () => {
    const first = sampleDataset(dataset, { perCategory: 2, seed: 42 });
    const second = sampleDataset(dataset, { perCategory: 2, seed: 42 });

    expect(first.map((item) => item.id)).toEqual(second.map((item) => item.id));
    expect(first).toHaveLength(4);
    expect(new Set(first.map((item) => item.category))).toEqual(
      new Set(["Data_Exfiltration", "System_RCE"]),
    );
    expect(first.filter((item) => item.category === "Data_Exfiltration")).toHaveLength(2);
    expect(first.filter((item) => item.category === "System_RCE")).toHaveLength(2);
    expect(new Set(first.map((item) => item.stratumKey)).size).toBe(4);
  });

  it("summarizes full and selected distributions", () => {
    const selected = sampleDataset(dataset, { perCategory: 1, seed: 7 });
    const summary = summarizeDataset(dataset, selected);

    expect(summary.total).toBe(8);
    expect(summary.selected).toBe(2);
    expect(summary.byCategory.Data_Exfiltration).toBe(4);
    expect(summary.byCategory.System_RCE).toBe(4);
    expect(summary.selectedByCategory.Data_Exfiltration).toBe(1);
    expect(summary.selectedByCategory.System_RCE).toBe(1);
  });
});

function hz(
  id: number,
  category: AgentHazardInstance["category"],
  jailbreak_method: AgentHazardInstance["jailbreak_method"],
): AgentHazardInstance {
  return {
    id,
    category,
    jailbreak_method,
    query: `query ${id}`,
    decomposed_query: [`turn ${id}`],
    comment: "",
    source: "test",
  };
}
