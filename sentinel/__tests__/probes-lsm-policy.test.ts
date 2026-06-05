import { describe, expect, it } from "vitest";
import type { AggregatedVerdict, Verdict } from "../channel/event.js";
import {
  PolicyTable,
  encodePolicyMessage,
  translateVerdict,
} from "../probes/lsm/policy.js";

function mkVerdict(
  partial: Partial<Verdict> & { reason: string; judgeId?: string },
): AggregatedVerdict {
  const final: Verdict = {
    action: "block",
    severity: "critical",
    reason: partial.reason,
    judgeId: partial.judgeId ?? "native:sensitive-path",
    confidence: 1,
    ...partial,
  };
  return { final, sources: [final] };
}

describe("translateVerdict", () => {
  it("translates sensitive-path verdict to open_path entry", () => {
    const e = translateVerdict(
      mkVerdict({
        reason: "native: sensitive path access blocked (foo); path=/etc/shadow",
      }),
      60_000,
      1000,
    );
    expect(e).not.toBeNull();
    expect(e!.kind).toBe("open_path");
    expect(e!.value).toBe("/etc/shadow");
    expect(e!.expiresAt).toBe(61_000);
  });

  it("translates kernel-escape verdict to exec_path entry", () => {
    const e = translateVerdict(
      mkVerdict({
        reason: "native: execve from scratch dir blocked (^/tmp/); path=/tmp/payload",
        judgeId: "native:kernel-escape",
      }),
      30_000,
      0,
    );
    expect(e).not.toBeNull();
    expect(e!.kind).toBe("exec_path");
    expect(e!.value).toBe("/tmp/payload");
  });

  it("translates connect verdict with addr= to connect_addr entry", () => {
    const e = translateVerdict(
      mkVerdict({
        reason: "blocked egress; addr=10.0.0.5",
        judgeId: "native:exfil",
      }),
      1000,
      0,
    );
    expect(e).not.toBeNull();
    expect(e!.kind).toBe("connect_addr");
    expect(e!.value).toBe("10.0.0.5");
  });

  it("returns null for verdicts without path / addr hints", () => {
    expect(
      translateVerdict(mkVerdict({ reason: "vague reason" }), 1000, 0),
    ).toBeNull();
  });
});

describe("PolicyTable", () => {
  it("ignores non-block verdicts", () => {
    const t = new PolicyTable({ ttlMs: 1000, maxEntries: 8, minSeverity: "high" });
    const v: AggregatedVerdict = {
      final: {
        action: "observe",
        severity: "high",
        reason: "path=/etc/shadow",
        judgeId: "native:sensitive-path",
        confidence: 0.5,
      },
      sources: [],
    };
    expect(t.ingest(v)).toBeNull();
    expect(t.size()).toBe(0);
  });

  it("ignores low-severity blocks", () => {
    const t = new PolicyTable({ ttlMs: 1000, maxEntries: 8, minSeverity: "high" });
    const v = mkVerdict({
      reason: "path=/etc/secret",
      severity: "medium",
    });
    expect(t.ingest(v)).toBeNull();
  });

  it("inserts and deduplicates identical entries", () => {
    let nowVal = 100;
    const t = new PolicyTable({
      ttlMs: 1000,
      maxEntries: 8,
      minSeverity: "high",
      now: () => nowVal,
    });
    t.ingest(
      mkVerdict({
        reason: "native: sensitive path access blocked (x); path=/etc/shadow",
      }),
    );
    nowVal = 500;
    const e2 = t.ingest(
      mkVerdict({
        reason: "native: sensitive path access blocked (x); path=/etc/shadow",
      }),
    );
    expect(t.size()).toBe(1);
    expect(e2!.expiresAt).toBe(1500); // refreshed TTL
  });

  it("expires entries past TTL", () => {
    let nowVal = 0;
    const t = new PolicyTable({
      ttlMs: 100,
      maxEntries: 8,
      minSeverity: "high",
      now: () => nowVal,
    });
    t.ingest(mkVerdict({ reason: "path=/etc/a" }));
    expect(t.size()).toBe(1);
    nowVal = 200;
    expect(t.size()).toBe(0);
  });

  it("evicts oldest beyond maxEntries", () => {
    let nowVal = 0;
    const t = new PolicyTable({
      ttlMs: 10_000,
      maxEntries: 2,
      minSeverity: "high",
      now: () => nowVal,
    });
    t.ingest(mkVerdict({ reason: "path=/etc/a" }));
    nowVal = 10;
    t.ingest(mkVerdict({ reason: "path=/etc/b" }));
    nowVal = 20;
    t.ingest(mkVerdict({ reason: "path=/etc/c" }));
    const values = t.list().map((e) => e.value);
    expect(values).not.toContain("/etc/a");
    expect(values).toContain("/etc/b");
    expect(values).toContain("/etc/c");
  });
});

describe("encodePolicyMessage", () => {
  it("produces JSONL terminated with a newline", () => {
    const s = encodePolicyMessage({ kind: "policy_clear" });
    expect(s.endsWith("\n")).toBe(true);
    expect(JSON.parse(s.trim())).toEqual({ kind: "policy_clear" });
  });
});
