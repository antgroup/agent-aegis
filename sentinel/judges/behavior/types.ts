import type { ProbeEvent, Verdict } from "../../channel/event.js";
import type { VerdictAction, VerdictSeverity } from "../../channel/schema.js";
import type { BufferedEvent, SessionEventBuffer } from "../../context/buffer.js";
import type { BehavioralSnapshot } from "../../context/snapshot.js";

export type BehaviorJudgeMode = "off" | "observe" | "enforce";

export interface BehaviorRuleConfig {
  enabled?: boolean;
  action?: VerdictAction;
  severity?: VerdictSeverity;
  confidence?: number;
  /** Optional time window for rules that scan recent events. */
  windowMs?: number;
  /** Named numeric thresholds; rule-specific direct fields are also accepted. */
  thresholds?: Record<string, number>;
  /** Named string pattern lists; rule-specific direct fields are also accepted. */
  patterns?: Record<string, string[]>;
  /** Extensible rule-specific options for future custom rules. */
  options?: Record<string, unknown>;
  [key: string]: unknown;
}

export interface BehaviorJudgeConfig {
  enabled?: boolean;
  mode?: BehaviorJudgeMode;
  minEvents?: number;
  recentCount?: number;
  rules?: Record<string, BehaviorRuleConfig | boolean>;
}

export interface BehaviorJudgeOptions {
  buffer: SessionEventBuffer;
  config?: BehaviorJudgeConfig;
}

export interface BehaviorRuleInput {
  event: ProbeEvent;
  events: BufferedEvent[];
  snapshot: BehavioralSnapshot;
  config: BehaviorRuleConfig;
}

export interface BehaviorRuleMatch {
  action?: VerdictAction;
  severity?: VerdictSeverity;
  confidence?: number;
  reason: string;
}

export interface BehaviorRule {
  readonly id: string;
  readonly defaultConfig: Required<Pick<BehaviorRuleConfig, "enabled" | "action" | "severity" | "confidence">> &
    BehaviorRuleConfig;
  evaluate(input: BehaviorRuleInput): BehaviorRuleMatch | null;
}

export type BehaviorCandidate = Verdict & { ruleId: string };
