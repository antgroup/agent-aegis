import { buildSnapshot } from "../../context/snapshot.js";
import { builtInBehaviorRules } from "./rules.js";
const JUDGE_ID = "behavior";
const ACTION_RANK = {
    allow: 0,
    observe: 1,
    block: 2,
};
const SEVERITY_RANK = {
    info: 0,
    low: 1,
    medium: 2,
    high: 3,
    critical: 4,
};
export { builtInBehaviorRules } from "./rules.js";
/**
 * Create a configurable behavior/sequence judge (M12).
 *
 * The judge consumes the M11.5 session buffer through a closure instead of
 * changing the core Judge interface. Rules are registry-driven and each rule
 * can be enabled/disabled and tuned through `BehaviorJudgeConfig.rules`.
 */
export function createBehaviorJudge(opts) {
    const config = opts.config ?? {};
    return {
        id: JUDGE_ID,
        weight: 1,
        async judge(event) {
            const mode = config.mode ?? "observe";
            if (config.enabled === false || mode === "off")
                return null;
            const sessionKey = event.sessionKey ?? "_default";
            const events = opts.buffer.getEvents(sessionKey);
            const minEvents = readPositiveInt(config.minEvents, 1);
            if (events.length < minEvents)
                return null;
            const snapshot = buildSnapshot(events, sessionKey, readPositiveInt(config.recentCount, 30));
            const candidates = [];
            for (const rule of builtInBehaviorRules) {
                const ruleConfig = resolveRuleConfig(rule, config.rules?.[rule.id]);
                if (ruleConfig.enabled === false)
                    continue;
                const match = rule.evaluate({ event, events, snapshot, config: ruleConfig });
                if (!match)
                    continue;
                candidates.push(toCandidate(rule, ruleConfig, match, mode, event.pid));
            }
            if (candidates.length === 0)
                return null;
            const pick = candidates.reduce((a, b) => (isStronger(b, a) ? b : a));
            return {
                action: pick.action,
                severity: pick.severity,
                confidence: pick.confidence,
                judgeId: pick.judgeId,
                reason: candidates.length === 1
                    ? pick.reason
                    : `${pick.reason}; matched rules=${candidates.map((c) => c.ruleId).join(",")}`,
                sideEffects: pick.sideEffects,
            };
        },
    };
}
function resolveRuleConfig(rule, override) {
    if (override === false)
        return { ...rule.defaultConfig, enabled: false };
    if (override === true || override === undefined)
        return { ...rule.defaultConfig };
    return { ...rule.defaultConfig, ...override };
}
function toCandidate(rule, config, match, mode, pid) {
    const configuredAction = match.action ?? config.action ?? rule.defaultConfig.action;
    const action = mode === "observe" && configuredAction === "block" ? "observe" : configuredAction;
    const severity = match.severity ?? config.severity ?? rule.defaultConfig.severity;
    const confidence = clampConfidence(match.confidence ?? config.confidence ?? rule.defaultConfig.confidence);
    return {
        ruleId: rule.id,
        action,
        severity,
        reason: match.reason,
        judgeId: `${JUDGE_ID}:${rule.id}`,
        confidence,
        sideEffects: [
            {
                kind: "log",
                level: severity === "high" || severity === "critical" ? "error" : "warn",
                message: `behavior rule ${rule.id} matched pid=${pid}: ${match.reason}`,
            },
        ],
    };
}
function isStronger(a, b) {
    if (ACTION_RANK[a.action] !== ACTION_RANK[b.action]) {
        return ACTION_RANK[a.action] > ACTION_RANK[b.action];
    }
    if (SEVERITY_RANK[a.severity] !== SEVERITY_RANK[b.severity]) {
        return SEVERITY_RANK[a.severity] > SEVERITY_RANK[b.severity];
    }
    return a.confidence > b.confidence;
}
function clampConfidence(v) {
    return typeof v === "number" && Number.isFinite(v) ? Math.max(0, Math.min(1, v)) : 0.5;
}
function readPositiveInt(v, fallback) {
    return typeof v === "number" && Number.isFinite(v) && v > 0 ? Math.floor(v) : fallback;
}
