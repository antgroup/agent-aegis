import type { AggregatedVerdict, ProbeEvent, Verdict, VerdictSideEffect } from "../channel/event.js";
import type { VerdictAction, VerdictSeverity } from "../channel/schema.js";
import type { AgentRuntimeCapabilities } from "../runtime/types.js";

export type ResponsePolicyMode = "off" | "observe" | "enforce";
export type ResponseStep = "observe" | "alert" | "throttle" | "block" | "kill" | "isolate";

export interface ResponsePolicyConfig {
  enabled?: boolean;
  mode?: ResponsePolicyMode;
  minAlertConfidence?: number;
  minBlockConfidence?: number;
  minKillConfidence?: number;
  blockSeverity?: VerdictSeverity;
  killSeverity?: VerdictSeverity;
  allowKill?: boolean;
  allowThrottle?: boolean;
  allowIsolate?: boolean;
  /** Never apply destructive process/system responses to these attribution buckets. */
  safeAttributions?: string[];
}

export interface ResponsePolicyOptions {
  config?: ResponsePolicyConfig;
  capabilities: AgentRuntimeCapabilities;
}

const SEVERITY_RANK: Record<VerdictSeverity, number> = {
  info: 0,
  low: 1,
  medium: 2,
  high: 3,
  critical: 4,
};

export class ResponsePolicyEngine {
  private readonly config: Required<ResponsePolicyConfig>;
  private readonly capabilities: AgentRuntimeCapabilities;

  constructor(opts: ResponsePolicyOptions) {
    const cfg = opts.config ?? {};
    this.capabilities = opts.capabilities;
    this.config = {
      enabled: cfg.enabled === true,
      mode: normalizeMode(cfg.mode),
      minAlertConfidence: normalizeConfidence(cfg.minAlertConfidence, 0.6),
      minBlockConfidence: normalizeConfidence(cfg.minBlockConfidence, 0.8),
      minKillConfidence: normalizeConfidence(cfg.minKillConfidence, 0.95),
      blockSeverity: normalizeSeverity(cfg.blockSeverity, "high"),
      killSeverity: normalizeSeverity(cfg.killSeverity, "critical"),
      allowKill: cfg.allowKill === true,
      allowThrottle: cfg.allowThrottle === true,
      allowIsolate: cfg.allowIsolate === true,
      safeAttributions: normalizeSafeAttributions(cfg.safeAttributions),
    };
  }

  apply(event: ProbeEvent, verdict: AggregatedVerdict): AggregatedVerdict {
    if (!this.config.enabled || this.config.mode === "off") return verdict;
    const plan = this.plan(event, verdict.final);
    if (plan.steps.length === 0) return verdict;

    const final: Verdict = {
      ...verdict.final,
      action: plan.finalAction,
      reason:
        plan.reason === verdict.final.reason
          ? verdict.final.reason
          : `${verdict.final.reason}; response=${plan.applied}`,
      sideEffects: mergeSideEffects(verdict.final.sideEffects, plan.sideEffects),
    };
    return { final, sources: verdict.sources };
  }

  private plan(event: ProbeEvent, verdict: Verdict): {
    steps: ResponseStep[];
    applied: ResponseStep;
    finalAction: VerdictAction;
    reason: string;
    sideEffects: VerdictSideEffect[];
  } {
    const desired = this.desiredSteps(event, verdict);
    if (desired.length === 0) {
      return {
        steps: [],
        applied: "observe",
        finalAction: verdict.action,
        reason: verdict.reason,
        sideEffects: [],
      };
    }
    const applied =
      this.config.mode === "observe"
        ? desired.includes("alert") ? "alert" : "observe"
        : desired[desired.length - 1];
    const mode = this.config.mode === "enforce" ? "enforce" : "observe";
    const finalAction = applied === "block" || applied === "kill" || applied === "isolate"
      ? "block"
      : verdict.action;
    const reason = `policy response planned: ${desired.join("->")} (applied=${applied})`;
    const sideEffects: VerdictSideEffect[] = [
      {
        kind: "response_plan",
        steps: desired,
        applied,
        mode,
        reason,
      },
    ];
    if (applied === "alert") {
      sideEffects.push({ kind: "notify_user", message: verdict.reason });
    }
    if (applied === "kill" && this.canKill(event)) {
      sideEffects.push({ kind: "terminate_process", pid: event.pid });
    }
    return { steps: desired, applied, finalAction, reason, sideEffects };
  }

  private desiredSteps(event: ProbeEvent, verdict: Verdict): ResponseStep[] {
    if (
      verdict.action === "allow" &&
      verdict.confidence < this.config.minAlertConfidence &&
      !severityAtLeast(verdict.severity, "medium")
    ) {
      return [];
    }

    const steps: ResponseStep[] = ["observe"];
    if (verdict.confidence >= this.config.minAlertConfidence || severityAtLeast(verdict.severity, "medium")) {
      steps.push("alert");
    }
    if (this.config.allowThrottle && severityAtLeast(verdict.severity, "high")) {
      steps.push("throttle");
    }
    if (
      verdict.action === "block" &&
      verdict.confidence >= this.config.minBlockConfidence &&
      severityAtLeast(verdict.severity, this.config.blockSeverity)
    ) {
      steps.push("block");
    }
    if (
      this.config.allowKill &&
      this.canKill(event) &&
      verdict.confidence >= this.config.minKillConfidence &&
      severityAtLeast(verdict.severity, this.config.killSeverity)
    ) {
      steps.push("kill");
    }
    if (this.config.allowIsolate && severityAtLeast(verdict.severity, "critical") && !this.isSafeAttribution(event)) {
      steps.push("isolate");
    }
    return steps;
  }

  private canKill(event: ProbeEvent): boolean {
    return (
      this.capabilities.canTerminateProcess &&
      event.pid > 0 &&
      !this.isSafeAttribution(event)
    );
  }

  private isSafeAttribution(event: ProbeEvent): boolean {
    const attr = typeof event.meta?.attribution === "string" ? event.meta.attribution : "unknown";
    return this.config.safeAttributions.includes(attr);
  }
}

function severityAtLeast(actual: VerdictSeverity, min: VerdictSeverity): boolean {
  return SEVERITY_RANK[actual] >= SEVERITY_RANK[min];
}

function normalizeMode(mode: unknown): ResponsePolicyMode {
  return mode === "off" || mode === "observe" || mode === "enforce" ? mode : "observe";
}

function normalizeSeverity(value: unknown, fallback: VerdictSeverity): VerdictSeverity {
  return value === "info" ||
    value === "low" ||
    value === "medium" ||
    value === "high" ||
    value === "critical"
    ? value
    : fallback;
}

function normalizeConfidence(value: unknown, fallback: number): number {
  return typeof value === "number" && Number.isFinite(value) && value >= 0 && value <= 1
    ? value
    : fallback;
}

function normalizeSafeAttributions(value: unknown): string[] {
  return Array.isArray(value) && value.every((item) => typeof item === "string")
    ? value
    : ["external", "unknown"];
}

function mergeSideEffects(
  existing: VerdictSideEffect[] | undefined,
  extra: VerdictSideEffect[],
): VerdictSideEffect[] {
  return [...(existing ?? []), ...extra];
}
