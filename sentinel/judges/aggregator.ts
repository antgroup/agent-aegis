import type { AggregatedVerdict, Verdict } from "../channel/event.js";
import type { AggregatorStrategy, VerdictAction, VerdictSeverity } from "../channel/schema.js";
import type { Judge } from "./base.js";
import type { ProbeEvent } from "../channel/event.js";

const ACTION_RANK: Record<VerdictAction, number> = {
  allow: 0,
  observe: 1,
  block: 2,
};

const SEVERITY_RANK: Record<VerdictSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

const ABSTAIN_VERDICT: Verdict = {
  action: "allow",
  severity: "info",
  reason: "all judges abstained",
  judgeId: "aggregator:abstain",
  confidence: 1,
};

/**
 * Run all registered judges against an event and aggregate the result.
 * Judges run in parallel; throws are treated as abstentions and logged via
 * `onJudgeError`.
 */
export async function runJudges(
  judges: Judge[],
  event: ProbeEvent,
  onJudgeError: (judgeId: string, err: unknown) => void,
): Promise<Verdict[]> {
  const settled = await Promise.allSettled(judges.map((j) => j.judge(event)));
  const out: Verdict[] = [];
  for (let i = 0; i < settled.length; i++) {
    const r = settled[i];
    const judge = judges[i];
    if (r.status === "rejected") {
      onJudgeError(judge.id, r.reason);
      continue;
    }
    if (r.value !== null && r.value !== undefined) {
      out.push(r.value);
    }
  }
  return out;
}

export function aggregate(
  verdicts: Verdict[],
  strategy: AggregatorStrategy,
): AggregatedVerdict {
  if (verdicts.length === 0) {
    return { final: { ...ABSTAIN_VERDICT }, sources: [] };
  }
  const final = strategy === "weighted" ? weightedVote(verdicts) : strictest(verdicts);
  return { final, sources: verdicts };
}

function strictest(verdicts: Verdict[]): Verdict {
  let pick = verdicts[0];
  for (const v of verdicts.slice(1)) {
    if (
      ACTION_RANK[v.action] > ACTION_RANK[pick.action] ||
      (ACTION_RANK[v.action] === ACTION_RANK[pick.action] &&
        SEVERITY_RANK[v.severity] > SEVERITY_RANK[pick.severity])
    ) {
      pick = v;
    }
  }
  return pick;
}

/**
 * Weighted vote across actions: each verdict contributes `confidence * weight`
 * to its chosen action; the action with the highest score wins. Ties go to
 * the stricter action.
 *
 * Reason / severity are taken from the highest-confidence verdict in the
 * winning bucket; sideEffects from all winning-bucket verdicts are merged.
 */
function weightedVote(verdicts: Verdict[]): Verdict {
  const buckets = new Map<VerdictAction, { score: number; members: Verdict[] }>();
  for (const v of verdicts) {
    const weight = (v as Verdict & { weight?: number }).weight ?? 1;
    const score = v.confidence * weight;
    const cur = buckets.get(v.action) ?? { score: 0, members: [] };
    cur.score += score;
    cur.members.push(v);
    buckets.set(v.action, cur);
  }

  let winnerAction: VerdictAction = "allow";
  let winnerScore = -1;
  for (const [action, bucket] of buckets) {
    if (
      bucket.score > winnerScore ||
      (bucket.score === winnerScore && ACTION_RANK[action] > ACTION_RANK[winnerAction])
    ) {
      winnerAction = action;
      winnerScore = bucket.score;
    }
  }

  const winners = buckets.get(winnerAction)!.members;
  const representative = winners.reduce((a, b) => (b.confidence > a.confidence ? b : a));
  const mergedSideEffects = winners.flatMap((w) => w.sideEffects ?? []);

  return {
    action: winnerAction,
    severity: winners.reduce(
      (sev, w) => (SEVERITY_RANK[w.severity] > SEVERITY_RANK[sev] ? w.severity : sev),
      "info" as VerdictSeverity,
    ),
    reason: representative.reason,
    judgeId: `aggregator:weighted(${winners.map((w) => w.judgeId).join(",")})`,
    confidence: Math.min(1, winnerScore / Math.max(1, verdicts.length)),
    sideEffects: mergedSideEffects.length > 0 ? mergedSideEffects : undefined,
  };
}
