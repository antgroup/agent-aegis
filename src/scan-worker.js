import { parentPort } from "node:worker_threads";
import { inspectEncodedCandidates } from "./encoding-guard.js";
import { buildGuardTextVariants, matchesPatternRiskRule, matchesVariantPatterns, } from "./rules.js";
import { SKILL_SCAN_REMOTE_BOOTSTRAP_RULES, SKILL_SCAN_RULES, SKILL_SCAN_SAFE_EXAMPLE_PATTERNS, } from "./security-strategies.js";
function splitSkillTextLines(text) {
    return text
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean);
}
function hasSafeExampleContext(text) {
    const variants = buildGuardTextVariants(text);
    return SKILL_SCAN_SAFE_EXAMPLE_PATTERNS.some((pattern) => pattern.test(variants.raw) || pattern.test(variants.normalized));
}
function matchesUnsafeLine(lines, patterns, compactPatterns = []) {
    return lines.some((line) => {
        if (hasSafeExampleContext(line)) {
            return false;
        }
        return matchesVariantPatterns(buildGuardTextVariants(line), patterns, compactPatterns);
    });
}
function matchesSkillRule(text, lines, rule) {
    if (rule.lineScope === "unsafe_only") {
        return matchesUnsafeLine(lines, rule.patterns, rule.compactPatterns ?? []);
    }
    return matchesPatternRiskRule(buildGuardTextVariants(text), rule);
}
function matchesBootstrapRule(text, lines, rule) {
    if (matchesUnsafeLine(lines, rule.directExecutionPatterns)) {
        return true;
    }
    const hasUnsafeDownload = matchesUnsafeLine(lines, rule.downloadPatterns);
    const hasUnsafeExecution = matchesUnsafeLine(lines, rule.executionPatterns);
    if (hasUnsafeDownload && hasUnsafeExecution) {
        return true;
    }
    return (rule.downloadPatterns.some((pattern) => pattern.test(text)) &&
        rule.executionPatterns.some((pattern) => pattern.test(text)) &&
        !hasSafeExampleContext(text));
}
function collectBaseSkillFindings(text) {
    const findings = new Set();
    const lines = splitSkillTextLines(text);
    for (const rule of SKILL_SCAN_RULES) {
        if (matchesSkillRule(text, lines, rule)) {
            findings.add(rule.flag);
        }
    }
    for (const rule of SKILL_SCAN_REMOTE_BOOTSTRAP_RULES) {
        if (matchesBootstrapRule(text, lines, rule)) {
            findings.add(rule.flag);
        }
    }
    return [...findings];
}
function analyzeDecodedSkillText(decoded) {
    return collectBaseSkillFindings(decoded).map((finding) => `encoded-${finding}`);
}
export function scanSkillText(text) {
    const findings = new Set(collectBaseSkillFindings(text));
    const encodedInspection = inspectEncodedCandidates(text, {
        analyzeDecoded: analyzeDecodedSkillText,
    });
    for (const finding of encodedInspection.findings) {
        for (const riskFlag of finding.riskFlags) {
            findings.add(riskFlag);
        }
    }
    return {
        trusted: findings.size === 0,
        findings: [...findings],
    };
}
if (parentPort) {
    const port = parentPort;
    port.on("message", (request) => {
        try {
            const result = scanSkillText(request.text);
            port.postMessage({
                requestId: request.requestId,
                result,
            });
        }
        catch (error) {
            port.postMessage({
                requestId: request.requestId,
                error: error instanceof Error ? error.message : String(error),
            });
        }
    });
}
