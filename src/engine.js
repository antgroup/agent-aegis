import { createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import path from "node:path";
import { BLOCK_REASON_DISPATCH_GUARD, AGENT_AEGIS_PLUGIN_ID, DEFENSE_EVENTS_FILENAME, SKILL_SCAN_EVENTS_FILENAME, STARTUP_SCAN_BUDGET_MS, } from "./config.js";
import { resolveAgentAegisPluginConfig, resolveAgentAegisStateDir, resolveSkillScanRoots, } from "./config.js";
import { buildDynamicPromptContext, buildLoopGuardStableArgsKey, buildStaticSystemContext, collectScriptArtifactRecords, collectSensitiveOutputValues, collectToolResultScanText, detectCommandObfuscationViolation, AEGIS_REFUSAL_PREFIX, detectDispatchGuardViolation, detectHighRiskCommand, detectUserRiskFlags, isOutboundToolCall, isThirdPartyWebToolResultMessage, normalizeToolName, normalizeToolParamsForGuard, reviewSuspiciousOutboundChain, resolveInlineExecutionViolation, resolveMemoryGuardViolation, resolveOutsideWorkspaceDeletionViolation, resolveProtectedPathCandidates, resolveProtectedPathViolation, resolveScriptProvenanceViolation, resolveSelfProtectionTextViolation, sanitizeAssistantMessage, sanitizeSensitiveOutputText, sanitizeToolResultMessage, scanToolResultText, } from "./rules.js";
import { TOOL_CALL_DEFENSE_STRATEGIES, } from "./security-strategies.js";
import { SkillScanService } from "./scan-service.js";
import { AgentAegisState } from "./state.js";
// ---------------------------------------------------------------------------
// Unified Defense Engine
// ---------------------------------------------------------------------------
export class AegisDefenseEngine {
    api;
    state;
    scanService;
    logger;
    config;
    stateDir;
    skillScanRoots;
    now;
    emitDefenseEvent;
    staticSystemContext;
    toolCallDefenseStrategies;
    constructor(api, options) {
        this.api = api;
        this.logger = createAegisLogger(this.api);
        this.now = options?.now ?? Date.now;
        this.stateDir = options?.stateDir ?? resolveAgentAegisStateDir(this.api);
        this.emitDefenseEvent = createDefenseEventWriter(this.stateDir);
        this.config = resolveAgentAegisPluginConfig({
            pluginConfig: this.api.pluginConfig,
            resolvePath: (p) => this.api.resolvePath(p),
        });
        this.skillScanRoots = options?.skillScanRoots ?? resolveSkillScanRoots(this.api);
        this.state = new AgentAegisState({ stateDir: this.stateDir, logger: this.logger, now: this.now });
        const emitSkillScanEvent = createSkillScanEventWriter(this.stateDir);
        this.scanService = new SkillScanService({
            state: this.state,
            logger: this.logger,
            now: this.now,
            runner: options?.scanRunner,
            onScanComplete: emitSkillScanEvent,
        });
        this.toolCallDefenseStrategies =
            options?.toolCallDefenseStrategies ?? TOOL_CALL_DEFENSE_STRATEGIES;
        this.staticSystemContext = this.config.promptGuardEnabled
            ? buildStaticSystemContext({
                selfProtectionEnabled: this.config.selfProtectionEnabled,
                toolCallEnforcementEnabled: this.config.toolCallEnforcementEnabled,
                protectedPaths: this.config.protectedPaths,
            })
            : undefined;
    }
    // -----------------------------------------------------------------------
    // Lifecycle & State
    // -----------------------------------------------------------------------
    async start() {
        this.logger.info("agent-aegis: 引擎启动", { event: "engine_start" });
        try {
            await this.state.loadPersistentState();
            this.logger.info("agent-aegis: 已恢复持久化状态", { event: "state_restored" });
        }
        catch (error) {
            this.logger.error("agent-aegis: 恢复持久化状态失败", {
                event: "state_restore_failed",
                reason: error instanceof Error ? error.message : String(error),
            });
        }
        try {
            const protectedRoots = this.config.selfProtectionEnabled
                ? await resolveProtectedRoots(this.api, this.stateDir, this.config)
                : [];
            this.state.setProtectedRoots(protectedRoots);
            this.logger.info("agent-aegis: 已解析受保护路径", {
                event: "protected_roots_ready",
                count: protectedRoots.length,
                enabled: this.config.selfProtectionEnabled,
            });
        }
        catch (error) {
            this.logger.error("agent-aegis: 解析受保护路径失败", {
                event: "protected_roots_failed",
                reason: error instanceof Error ? error.message : String(error),
            });
        }
        if (this.config.selfProtectionEnabled) {
            try {
                const integrityRecord = await buildSelfIntegrityRecord({
                    api: this.api,
                    stateDir: this.stateDir,
                    protectedRoots: this.state.getProtectedRoots(),
                });
                this.state.setSelfIntegrityRecord(integrityRecord);
                await this.state.persistSelfIntegrity();
                this.logger.info("agent-aegis: 已刷新自完整性记录", { event: "self_integrity_refreshed" });
            }
            catch (error) {
                this.logger.error("agent-aegis: 刷新自完整性记录失败", {
                    event: "self_integrity_failed",
                    reason: error instanceof Error ? error.message : String(error),
                });
            }
        }
        try {
            if (!this.config.skillScanEnabled) {
                this.logger.info("agent-aegis: 配置已关闭 skill 扫描", { event: "skill_scan_disabled" });
                return;
            }
            if (this.config.skillRoots.length > 0) {
                this.logger.warn("agent-aegis: 已忽略过时的 skillRoots 配置", {
                    event: "skill_scan_legacy_roots_ignored",
                    ignoredCount: this.config.skillRoots.length,
                });
            }
            this.scanService.start();
            if (this.config.startupSkillScan) {
                void this.scanService
                    .scanRoots({ roots: this.skillScanRoots, budgetMs: STARTUP_SCAN_BUDGET_MS })
                    .catch((error) => {
                    this.logger.warn("agent-aegis: 启动阶段的 skill 扫描已降级", {
                        event: "startup_skill_scan_failed",
                        reason: error instanceof Error ? error.message : String(error),
                    });
                });
            }
        }
        catch (error) {
            this.logger.error("agent-aegis: 启动 skill 扫描服务失败", {
                event: "skill_scan_start_failed",
                reason: error instanceof Error ? error.message : String(error),
            });
        }
    }
    // -----------------------------------------------------------------------
    // Handlers
    // -----------------------------------------------------------------------
    checkUserInput(content, sessionKey) {
        const startedAt = this.now();
        if (sessionKey && content) {
            this.state.noteLastUserInput(sessionKey, content);
        }
        logDefenseStart(this.logger, {
            hook: "message_received",
            mechanism: "user_risk_scan",
            sessionKey,
        });
        if (!this.config.userRiskScanEnabled) {
            this.finishCheck("message_received", "user_risk_scan", sessionKey, "disabled", startedAt);
            return;
        }
        if (!sessionKey) {
            this.finishCheck("message_received", "user_risk_scan", sessionKey, "skipped_missing_session", startedAt);
            return;
        }
        const match = detectUserRiskFlags(content ?? "");
        const durationMs = this.now() - startedAt;
        if (match.flags.length === 0) {
            this.finishCheck("message_received", "user_risk_scan", sessionKey, "clear", startedAt);
            return;
        }
        this.state.noteUserRisk(sessionKey, match.flags);
        this.emitDefenseEvent({
            timestamp: this.now(),
            defense: "user_risk_scan",
            result: "observed",
            reason: `检测到风险标记: ${match.flags.join(", ")}`,
            details: { flags: match.flags },
            userInput: (content ?? "").slice(0, 500),
        });
        this.logger.warn("agent-aegis: 检测到用户风险请求", {
            event: "user_risk_detected",
            hook: "message_received",
            sessionKey,
            flags: match.flags,
        });
        logDefenseResult(this.logger, {
            hook: "message_received",
            mechanism: "user_risk_scan",
            sessionKey,
            result: "risk_detected",
            durationMs,
            flagCount: match.flags.length,
        }, "warn");
        this.finishCheck("message_received", "user_risk_scan", sessionKey, "risk_detected", startedAt);
    }
    redactOutboundMessage(content, to, sessionKey) {
        const startedAt = this.now();
        logDefenseStart(this.logger, {
            hook: "message_sending",
            mechanism: "output_redaction",
            sessionKey,
        });
        if (!this.config.outputRedactionEnabled) {
            this.finishCheck("message_sending", "output_redaction", sessionKey, "disabled", startedAt);
            return undefined;
        }
        const observedSecrets = sessionKey ? this.state.peekObservedSecrets(sessionKey) : [];
        const sanitized = sanitizeSensitiveOutputText(content, { observedSecrets });
        const durationMs = this.now() - startedAt;
        if (sanitized.changed) {
            this.emitDefenseEvent({
                timestamp: this.now(),
                defense: "output_redaction",
                result: "observed",
                reason: `脱敏 ${sanitized.redactionCount} 处敏感内容`,
                details: { redactionCount: sanitized.redactionCount, matchedKeywords: sanitized.matchedKeywords },
            });
            this.logger.warn("agent-aegis: 已脱敏对外发送消息中的敏感内容", {
                event: "outbound_message_redacted",
                hook: "message_sending",
                sessionKey,
                to,
                redactionCount: sanitized.redactionCount,
                matchedKeywords: sanitized.matchedKeywords,
                durationMs,
            });
        }
        logDefenseResult(this.logger, {
            hook: "message_sending",
            mechanism: "output_redaction",
            sessionKey,
            result: sanitized.changed ? "redacted" : "clear",
            durationMs,
            redactionCount: sanitized.redactionCount,
        });
        this.finishCheck("message_sending", "output_redaction", sessionKey, sanitized.changed ? "redacted" : "clear", startedAt);
        return sanitized.changed ? sanitized.value : undefined;
    }
    async buildPromptContext(prompt, sessionKey) {
        const startedAt = this.now();
        let syntheticState;
        if (sessionKey && prompt?.trim()) {
            this.state.notePromptSnapshot(sessionKey, prompt);
        }
        logDefenseStart(this.logger, {
            hook: "before_prompt_build",
            mechanism: "prompt_guard",
            sessionKey,
        });
        if (!this.config.promptGuardEnabled) {
            this.finishCheck("before_prompt_build", "prompt_guard", sessionKey, "disabled", startedAt);
            return undefined;
        }
        if (this.config.skillScanEnabled) {
            try {
                const skillReview = await this.scanService.inspectTurnSkillRisks({ roots: this.skillScanRoots });
                if (skillReview.riskyAssessments.length > 0) {
                    const skillRiskFlags = [
                        ...new Set(skillReview.riskyAssessments.flatMap((a) => a.findings)),
                    ];
                    const riskySkills = [
                        ...new Set(skillReview.riskyAssessments.map((a) => a.skillId)),
                    ];
                    this.logger.warn("agent-aegis: 已将高风险 skill 提升为提示防护", {
                        event: "skill_prompt_guard_triggered",
                        hook: "before_prompt_build",
                        sessionKey,
                        riskySkillCount: riskySkills.length,
                        riskySkills,
                        skillRiskFlags,
                    });
                    if (sessionKey) {
                        this.state.noteSkillRisk(sessionKey, { flags: skillRiskFlags, skillIds: riskySkills });
                    }
                    else {
                        syntheticState = createSyntheticSkillRiskState({
                            now: this.now(),
                            skillRiskFlags,
                            riskySkills,
                        });
                    }
                }
            }
            catch (error) {
                this.logger.error("agent-aegis: 本轮 skill 风险复核失败", {
                    event: "skill_prompt_guard_failed",
                    hook: "before_prompt_build",
                    reason: error instanceof Error ? error.message : String(error),
                });
            }
        }
        const currentState = sessionKey ? this.state.consumePromptState(sessionKey) : syntheticState;
        const dynamicPromptContext = buildDynamicPromptContext(currentState);
        const prependSystemContext = joinPresentTextSegments([
            this.staticSystemContext,
            dynamicPromptContext,
        ]);
        const durationMs = this.now() - startedAt;
        if (currentState?.prependNeeded) {
            this.logger.info("agent-aegis: 已注入提示防护", {
                event: "prompt_safeguards_injected",
                hook: "before_prompt_build",
                sessionKey,
            });
        }
        if (dynamicPromptContext && currentState) {
            const triggeredFlags = this.collectTriggeredFlags(currentState);
            this.emitDefenseEvent({
                timestamp: this.now(),
                defense: "prompt_guard",
                result: "observed",
                reason: `提示防护已注入安全规则: ${triggeredFlags.join(", ")}`,
                details: {
                    hook: "before_prompt_build",
                    userRiskFlags: currentState.userRiskFlags,
                    runtimeRiskFlags: currentState.runtimeRiskFlags,
                    toolResultSuspicious: currentState.toolResultSuspicious,
                    toolResultOversize: currentState.toolResultOversize,
                    toolResultRiskFlags: currentState.toolResultRiskFlags,
                    skillRiskFlags: currentState.skillRiskFlags,
                    riskySkills: currentState.riskySkills,
                },
                userInput: sessionKey ? this.state.peekLastUserInput(sessionKey) : undefined,
            });
        }
        if (!prependSystemContext) {
            this.finishCheck("before_prompt_build", "prompt_guard", sessionKey, "no_context_injected", startedAt);
            return undefined;
        }
        const result = this.staticSystemContext && dynamicPromptContext ? "static_and_dynamic_injected" : this.staticSystemContext ? "static_only_injected" : "dynamic_only_injected";
        logDefenseResult(this.logger, {
            hook: "before_prompt_build",
            mechanism: "prompt_guard",
            sessionKey,
            result,
            durationMs,
        });
        this.finishCheck("before_prompt_build", "prompt_guard", sessionKey, result, startedAt);
        return prependSystemContext;
    }
    checkDispatch(content, sessionKey, hookName = "before_dispatch") {
        const startedAt = this.now();
        logDefenseStart(this.logger, { hook: hookName, mechanism: "dispatch_guard", sessionKey });
        if (!this.config.dispatchGuardEnabled) {
            this.finishCheck(hookName, "dispatch_guard", sessionKey, "disabled", startedAt);
            return undefined;
        }
        const trimmedContent = content?.trim();
        if (!trimmedContent) {
            this.finishCheck(hookName, "dispatch_guard", sessionKey, "empty_content", startedAt);
            return undefined;
        }
        const violation = detectDispatchGuardViolation(trimmedContent, this.config.protectedPaths);
        if (!violation.blocked) {
            this.finishCheck(hookName, "dispatch_guard", sessionKey, "clear", startedAt);
            return undefined;
        }
        const reason = violation.reason ?? BLOCK_REASON_DISPATCH_GUARD;
        const result = this.config.dispatchGuardMode === "enforce" ? "blocked" : "observed";
        this.emitDefenseEvent({
            timestamp: this.now(),
            defense: "dispatch_guard",
            result,
            reason,
            details: { hook: hookName, flags: violation.flags, mode: this.config.dispatchGuardMode },
            userInput: trimmedContent,
        });
        if (this.config.dispatchGuardMode === "enforce") {
            this.logger.warn(`agent-aegis: ${hookName} 已拦截危险操作请求`, {
                event: "dispatch_guard_blocked",
                hook: hookName,
                sessionKey,
                flags: violation.flags,
            });
            this.finishCheck(hookName, "dispatch_guard", sessionKey, "blocked", startedAt);
            return {
                block: true,
                reason,
                text: `[AgentAegis] ${reason}\n\n所有破坏性操作必须通过标准 tool call 执行，不能绕过安全 hook。如确需执行，请联系管理员调整安全策略。`,
            };
        }
        this.logger.info(`agent-aegis: ${hookName} 已观测到危险操作请求（observe 模式）`, {
            event: "dispatch_guard_observed",
            hook: hookName,
            sessionKey,
            flags: violation.flags,
        });
        this.finishCheck(hookName, "dispatch_guard", sessionKey, "observed", startedAt);
        return undefined;
    }
    checkToolCall(toolName, params, runId, sessionKey) {
        const startedAt = this.now();
        const normalizedToolName = normalizeToolName(toolName);
        const normalizedParams = normalizeToolParamsForGuard(params ?? {});
        const selfProtectionMode = this.config.selfProtectionMode;
        const commandBlockMode = this.config.commandBlockMode;
        const encodingGuardMode = this.config.encodingGuardMode;
        const scriptProvenanceGuardMode = this.config.scriptProvenanceGuardMode;
        const memoryGuardMode = this.config.memoryGuardMode;
        const loopGuardMode = this.config.loopGuardMode;
        const exfiltrationGuardMode = this.config.exfiltrationGuardMode;
        const toolCallModes = {
            selfProtection: selfProtectionMode,
            commandBlock: commandBlockMode,
            encodingGuard: encodingGuardMode,
            commandObfuscation: mergeDefenseModes(commandBlockMode, encodingGuardMode),
            scriptProvenanceGuard: scriptProvenanceGuardMode,
            memoryGuard: memoryGuardMode,
            loopGuard: loopGuardMode,
            exfiltrationGuard: exfiltrationGuardMode,
        };
        logDefenseStart(this.logger, { hook: "before_tool_call", mechanism: "tool_call_guard", sessionKey, runId, toolName: normalizedToolName });
        const hasAnyEnabledStrategy = this.toolCallDefenseStrategies.some((strategy) => isDefenseEnabled(resolveToolCallDefenseMode(toolCallModes, strategy.modeSource)));
        if (!hasAnyEnabledStrategy) {
            this.finishCheck("before_tool_call", "tool_call_guard", sessionKey, "disabled", startedAt, { runId, toolName: normalizedToolName });
            return undefined;
        }
        const baseDir = process.cwd();
        const protectedRoots = isDefenseEnabled(selfProtectionMode) ? this.state.getProtectedRoots() : [];
        const pathCandidates = resolveProtectedPathCandidates(normalizedToolName, normalizedParams, baseDir);
        const previousToolCalls = runId ? this.state.peekRunToolCalls(runId) : [];
        const observedSecrets = sessionKey ? this.state.peekObservedSecrets(sessionKey) : [];
        if (runId && observedSecrets.length > 0) {
            this.state.noteRunSecretFingerprints(runId, {
                sessionKey,
                fingerprints: buildSecretFingerprints(observedSecrets, "observed-secret", this.now()),
            });
        }
        const runSecurityState = runId ? this.state.peekRunSecurityState(runId) : undefined;
        const promptSnapshot = sessionKey ? this.state.peekPromptSnapshot(sessionKey) : undefined;
        const commandText = readCommandText(normalizedParams);
        const toolCallContext = {
            toolName: normalizedToolName,
            params: normalizedParams,
            commandText,
            sessionKey,
            runId,
            baseDir,
            protectedRoots,
            pathCandidates,
            previousToolCalls,
            observedSecrets,
            runSecurityState,
            promptSnapshot,
            protectedSkills: this.config.protectedSkills,
            protectedPlugins: this.config.protectedPlugins,
            now: this.now,
            modes: toolCallModes,
            helpers: {
                resolveSelfProtectionTextViolation,
                resolveOutsideWorkspaceDeletionViolation,
                resolveProtectedPathViolation,
                detectCommandObfuscationViolation,
                detectHighRiskCommand,
                resolveInlineExecutionViolation,
                resolveMemoryGuardViolation,
                resolveScriptProvenanceViolation,
                reviewSuspiciousOutboundChain,
                buildLoopGuardStableArgsKey,
                isOutboundToolCall,
            },
            state: {
                incrementLoopCounter: (sk, rid, key) => this.state.incrementLoopCounter(sk, rid, key),
                noteRunSecuritySignals: (rid, payload) => this.state.noteRunSecuritySignals(rid, payload),
                noteRuntimeRisk: (sk, flags) => this.state.noteRuntimeRisk(sk, flags),
                noteRunToolCall: (rid, record) => this.state.noteRunToolCall(rid, record),
            },
        };
        let result = undefined;
        for (const strategy of this.toolCallDefenseStrategies) {
            if (!strategy.appliesTo(toolCallContext))
                continue;
            const strategyStartedAt = this.now();
            logDefenseStart(this.logger, { hook: "before_tool_call", mechanism: strategy.id, sessionKey, runId, toolName: normalizedToolName });
            const evaluation = strategy.evaluate(toolCallContext);
            const durationMs = this.now() - strategyStartedAt;
            const resultMeta = { hook: "before_tool_call", mechanism: strategy.id, sessionKey, runId, toolName: normalizedToolName, result: evaluation.result, durationMs, ...(evaluation.extra ?? {}) };
            if (evaluation.result === "blocked") {
                this.emitDefenseEvent({
                    timestamp: this.now(),
                    defense: strategy.id,
                    result: "blocked",
                    toolName: normalizedToolName,
                    reason: evaluation.reason,
                    details: evaluation.extra,
                    commandText,
                    toolParams: normalizedParams,
                    userInput: sessionKey ? this.state.peekLastUserInput(sessionKey) : undefined,
                });
                this.logger.warn(strategy.blockedMessage ?? "agent-aegis: 已阻止风险工具调用", {
                    event: "tool_call_blocked",
                    hook: "before_tool_call",
                    toolName: normalizedToolName,
                    sessionKey,
                    runId,
                    reason: evaluation.reason,
                    ...(evaluation.extra ?? {}),
                });
                logDefenseFinish(this.logger, resultMeta);
                this.finishCheck("before_tool_call", "tool_call_guard", sessionKey, "blocked", startedAt, { blockedBy: strategy.id });
                return { block: true, reason: evaluation.reason, defense: strategy.id };
            }
            if (evaluation.result === "observed") {
                this.emitDefenseEvent({
                    timestamp: this.now(),
                    defense: strategy.id,
                    result: "observed",
                    toolName: normalizedToolName,
                    reason: evaluation.reason ?? "unknown",
                    details: evaluation.extra,
                    commandText,
                    toolParams: normalizedParams,
                    userInput: sessionKey ? this.state.peekLastUserInput(sessionKey) : undefined,
                });
                logObservedToolCall({
                    logger: this.logger,
                    mechanism: strategy.id,
                    message: strategy.observedMessage ?? "agent-aegis: 观察者模式命中风险工具调用，已放行",
                    sessionKey,
                    runId,
                    toolName: normalizedToolName,
                    reason: evaluation.reason ?? "unknown",
                    durationMs,
                    extra: evaluation.extra,
                });
                if (evaluation.emitResultLog) {
                    logDefenseResult(this.logger, resultMeta, evaluation.level ?? "warn");
                }
                logDefenseFinish(this.logger, resultMeta);
                if (!result) {
                    result = { block: false, reason: evaluation.reason, defense: strategy.id };
                }
                continue;
            }
            logDefenseResult(this.logger, resultMeta, evaluation.level ?? "info");
            logDefenseFinish(this.logger, resultMeta);
        }
        if (runId) {
            this.state.noteRunToolCall(runId, { runId, sessionKey, toolName: normalizedToolName, params: normalizedParams, timestamp: this.now() });
        }
        this.finishCheck("before_tool_call", "tool_call_guard", sessionKey, result ? "observed" : "allowed", startedAt, { runId, toolName: normalizedToolName });
        return result;
    }
    trackToolCallResult(toolName, params, error, runId, sessionKey) {
        const normalizedToolName = normalizeToolName(toolName);
        const normalizedParams = normalizeToolParamsForGuard(params ?? {});
        if (!runId)
            return;
        if (!error && this.config.scriptProvenanceGuardEnabled) {
            const artifacts = collectScriptArtifactRecords(normalizedToolName, normalizedParams, {
                runId,
                sessionKey,
                timestamp: this.now(),
                baseDir: process.cwd(),
            });
            if (artifacts.length > 0) {
                this.state.noteRunScriptArtifacts(runId, { sessionKey, artifacts });
                const derivedSignals = deriveScriptArtifactSignals(artifacts);
                this.state.noteRunSecuritySignals(runId, {
                    sessionKey,
                    sourceSignals: derivedSignals.sourceSignals,
                    transformSignals: derivedSignals.transformSignals,
                    sinkSignals: derivedSignals.sinkSignals,
                    runtimeRiskFlags: derivedSignals.runtimeRiskFlags,
                });
                if (sessionKey && derivedSignals.runtimeRiskFlags.length > 0) {
                    this.state.noteRuntimeRisk(sessionKey, derivedSignals.runtimeRiskFlags);
                }
                this.logger.info("agent-aegis: 已记录本轮新产生的脚本产物", {
                    event: "script_artifacts_recorded",
                    hook: "after_tool_call",
                    sessionKey,
                    runId,
                    toolName: normalizedToolName,
                    artifactCount: artifacts.length,
                });
            }
        }
        const calls = this.state.peekRunToolCalls(runId);
        if (calls.length > 0) {
            const blockedCount = calls.filter((call) => call.blocked).length;
            this.logger.info("agent-aegis: 已更新同 run 工具调用链", {
                event: "tool_call_chain_updated",
                hook: "after_tool_call",
                sessionKey,
                runId,
                totalCalls: calls.length,
                blockedCalls: blockedCount,
            });
        }
    }
    handleLlmOutput(texts, model, provider) {
        if (!this.config.allDefensesEnabled)
            return;
        for (const text of texts) {
            if (!text.includes(AEGIS_REFUSAL_PREFIX))
                continue;
            const idx = text.indexOf(AEGIS_REFUSAL_PREFIX);
            const afterPrefix = text.slice(idx + AEGIS_REFUSAL_PREFIX.length).split("\n")[0].trim();
            const reason = afterPrefix || "LLM 自行拒绝（未提供具体原因）";
            this.emitDefenseEvent({
                timestamp: this.now(),
                defense: "prompt_self_block",
                result: "blocked",
                reason,
                details: { hook: "llm_output", model, provider },
            });
            this.logger.info("agent-aegis: LLM 输出包含 Aegis 拒绝标记", {
                event: "prompt_self_block_detected",
                hook: "llm_output",
                model,
                provider,
                reason,
            });
            break;
        }
    }
    redactAssistantMessage(message, sessionKey) {
        const startedAt = this.now();
        logDefenseStart(this.logger, { hook: "before_message_write", mechanism: "output_redaction", sessionKey });
        if (!this.config.outputRedactionEnabled) {
            this.finishCheck("before_message_write", "output_redaction", sessionKey, "disabled", startedAt);
            return undefined;
        }
        const observedSecrets = sessionKey ? this.state.peekObservedSecrets(sessionKey) : [];
        const sanitized = sanitizeAssistantMessage(message, { observedSecrets });
        const durationMs = this.now() - startedAt;
        if (sanitized.changed) {
            this.emitDefenseEvent({
                timestamp: this.now(),
                defense: "output_redaction",
                result: "observed",
                reason: `脱敏 assistant 输出 ${sanitized.redactionCount} 处`,
                details: { redactionCount: sanitized.redactionCount, matchedKeywords: sanitized.matchedKeywords },
            });
            this.logger.warn("agent-aegis: 已脱敏 assistant 输出中的敏感内容", {
                event: "assistant_output_redacted",
                hook: "before_message_write",
                sessionKey,
                redactionCount: sanitized.redactionCount,
                matchedKeywords: sanitized.matchedKeywords,
                durationMs,
            });
        }
        logDefenseResult(this.logger, {
            hook: "before_message_write",
            mechanism: "output_redaction",
            sessionKey,
            result: sanitized.changed ? "redacted" : "clear",
            durationMs,
            redactionCount: sanitized.redactionCount,
        });
        this.finishCheck("before_message_write", "output_redaction", sessionKey, sanitized.changed ? "redacted" : "clear", startedAt);
        return sanitized.changed ? { message: sanitized.message, changed: true } : undefined;
    }
    scanToolResult(message, sessionKey) {
        const startedAt = this.now();
        logDefenseStart(this.logger, { hook: "before_message_write", mechanism: "tool_result_scan", sessionKey });
        if (!this.config.toolResultScanEnabled) {
            this.finishCheck("before_message_write", "tool_result_scan", sessionKey, "disabled", startedAt);
            return undefined;
        }
        if (!sessionKey || message.role !== "toolResult") {
            this.finishCheck("before_message_write", "tool_result_scan", sessionKey, !sessionKey ? "skipped_missing_session" : "skipped_non_tool_result", startedAt);
            return undefined;
        }
        try {
            const thirdPartyWebContent = isThirdPartyWebToolResultMessage(message);
            const toolName = typeof message.toolName === "string" ? message.toolName : undefined;
            const sanitized = sanitizeToolResultMessage(message);
            const extracted = collectToolResultScanText(sanitized.message);
            const observedSecrets = collectSensitiveOutputValues(extracted.text);
            if (observedSecrets.length > 0) {
                this.state.noteObservedSecrets(sessionKey, observedSecrets);
            }
            const outcome = scanToolResultText(extracted.text, extracted.oversize);
            this.state.noteToolResult(sessionKey, outcome);
            const encodedRiskFlags = outcome.riskFlags.filter((flag) => flag.startsWith("encoded-"));
            if (encodedRiskFlags.length > 0) {
                this.state.noteRuntimeRisk(sessionKey, encodedRiskFlags);
            }
            const durationMs = this.now() - startedAt;
            if (outcome.suspicious || outcome.oversize || outcome.riskFlags.length > 0 || sanitized.removedTokenCount > 0) {
                this.emitDefenseEvent({
                    timestamp: this.now(),
                    defense: "tool_result_scan",
                    result: "observed",
                    toolName: typeof message.toolName === "string" ? message.toolName : undefined,
                    reason: `风险标记: ${outcome.riskFlags.join(", ") || "suspicious/oversize"}`,
                    details: { flags: outcome.riskFlags, suspicious: outcome.suspicious, oversize: outcome.oversize },
                });
                this.logger.warn("agent-aegis: 已完成工具结果审查", { event: "tool_result_reviewed", suspicious: outcome.suspicious, flags: outcome.riskFlags, durationMs });
            }
            this.finishCheck("before_message_write", "tool_result_scan", sessionKey, "risk_detected", startedAt);
            return sanitized.changed ? { message: sanitized.message, changed: true } : undefined;
        }
        catch (error) {
            this.state.markToolResultSeen(sessionKey);
            this.logger.error("agent-aegis: 工具结果扫描已降级", {
                event: "tool_result_scan_failed",
                reason: error instanceof Error ? error.message : String(error),
            });
            this.finishCheck("before_message_write", "tool_result_scan", sessionKey, "degraded", startedAt);
            return undefined;
        }
    }
    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------
    finishCheck(hook, mechanism, sessionKey, result, startedAt, extra) {
        const durationMs = this.now() - startedAt;
        logDefenseFinish(this.logger, { hook, mechanism, sessionKey, result, durationMs, ...extra });
    }
    collectTriggeredFlags(state) {
        const flags = [];
        if (state.userRiskFlags.length > 0)
            flags.push(...state.userRiskFlags);
        if (state.runtimeRiskFlags.length > 0)
            flags.push(...state.runtimeRiskFlags);
        if (state.toolResultSuspicious)
            flags.push("tool_result_suspicious");
        if (state.toolResultOversize)
            flags.push("tool_result_oversize");
        if (state.toolResultRiskFlags.length > 0)
            flags.push(...state.toolResultRiskFlags);
        if (state.riskySkills.length > 0)
            flags.push(...state.riskySkills.map((s) => `risky_skill:${s}`));
        return flags;
    }
}
// ---------------------------------------------------------------------------
// Utility functions (moved from handlers.ts)
// ---------------------------------------------------------------------------
function createAegisLogger(api) {
    const serializeLogMeta = (meta) => {
        if (!meta || Object.keys(meta).length === 0)
            return "";
        try {
            return ` ${JSON.stringify(meta)}`;
        }
        catch {
            return ' {"meta":"[unserializable]"}';
        }
    };
    return {
        debug: api.logger.debug
            ? (message, meta) => api.logger.debug?.(`${message}${serializeLogMeta(meta)}`)
            : undefined,
        info: (message, meta) => api.logger.info(`${message}${serializeLogMeta(meta)}`),
        warn: (message, meta) => api.logger.warn(`${message}${serializeLogMeta(meta)}`),
        error: (message, meta) => api.logger.error(`${message}${serializeLogMeta(meta)}`),
    };
}
function createDefenseEventWriter(stateDir) {
    const eventsPath = path.join(stateDir, DEFENSE_EVENTS_FILENAME);
    let ensured = false;
    return (record) => {
        const line = JSON.stringify(record) + "\n";
        const doWrite = async () => {
            if (!ensured) {
                await fs.mkdir(stateDir, { recursive: true });
                ensured = true;
            }
            await fs.appendFile(eventsPath, line, "utf8");
        };
        doWrite().catch(() => { });
    };
}
function createSkillScanEventWriter(stateDir) {
    const eventsPath = path.join(stateDir, SKILL_SCAN_EVENTS_FILENAME);
    let ensured = false;
    return (record) => {
        const line = JSON.stringify(record) + "\n";
        const doWrite = async () => {
            if (!ensured) {
                await fs.mkdir(stateDir, { recursive: true });
                ensured = true;
            }
            await fs.appendFile(eventsPath, line, "utf8");
        };
        doWrite().catch(() => { });
    };
}
function logDefenseStart(logger, meta) {
    logger.info("agent-aegis: 开始执行防御检查", { event: "defense_check_started", ...meta });
}
function logDefenseFinish(logger, meta) {
    logger.info("agent-aegis: 防御检查结束", { event: "defense_check_finished", ...meta });
}
function logDefenseResult(logger, meta, level = "info") {
    const message = "agent-aegis: 防御检查结果";
    const payload = { event: "defense_check_result", ...meta };
    if (level === "warn")
        logger.warn(message, payload);
    else
        logger.info(message, payload);
}
function mergeDefenseModes(...modes) {
    if (modes.includes("enforce"))
        return "enforce";
    if (modes.includes("observe"))
        return "observe";
    return "off";
}
function resolveToolCallDefenseMode(modes, source) {
    const sources = Array.isArray(source) ? source : [source];
    return mergeDefenseModes(...sources.map((entry) => modes[entry]));
}
function isDefenseEnabled(mode) {
    return mode !== "off";
}
function logObservedToolCall(params) {
    params.logger.warn(params.message, { event: "tool_call_observed", hook: "before_tool_call", mechanism: params.mechanism, toolName: params.toolName, sessionKey: params.sessionKey, runId: params.runId, reason: params.reason, mode: "observe", durationMs: params.durationMs, ...(params.extra ?? {}) });
}
async function resolveRealPath(input) {
    if (!input?.trim())
        return undefined;
    try {
        return await fs.realpath(input);
    }
    catch {
        return path.resolve(input);
    }
}
async function resolveProtectedRoots(api, stateDir, config) {
    const stateRoot = path.resolve(api.runtime.state.resolveStateDir());
    const candidates = new Set();
    const append = async (entry) => {
        if (!entry?.trim())
            return;
        const resolved = path.resolve(entry);
        candidates.add(resolved);
        const real = await resolveRealPath(resolved);
        if (real)
            candidates.add(real);
    };
    await append(api.rootDir);
    await append(stateDir);
    for (const p of config.protectedPaths)
        await append(p);
    for (const e of config.extraProtectedRoots)
        await append(e);
    for (const s of config.protectedSkills) {
        await append(path.join(stateRoot, "skills", s));
        await append(path.join(stateRoot, "workspace", "skills", s));
    }
    for (const p of config.protectedPlugins) {
        await append(path.join(stateRoot, "extensions", p));
        await append(path.join(stateRoot, "plugins", p));
    }
    return [...candidates].sort((a, b) => a.localeCompare(b));
}
async function buildSelfIntegrityRecord(params) {
    const rootDir = params.api.rootDir ? path.resolve(params.api.rootDir) : undefined;
    const rootRealPath = await resolveRealPath(rootDir);
    const fingerprints = {};
    const SELF_INTEGRITY_FILES = ["index.ts", "runtime-api.ts", "openclaw.plugin.json", "package.json", "src/config.ts", "src/types.ts", "src/state.ts", "src/rules.ts", "src/scan-service.ts", "src/scan-worker.ts", "src/scan-worker.js", "src/handlers.ts"];
    if (rootDir) {
        for (const relativePath of SELF_INTEGRITY_FILES) {
            const absolutePath = path.join(rootDir, relativePath);
            try {
                const content = await fs.readFile(absolutePath);
                fingerprints[relativePath] = createHash("sha256").update(content).digest("hex").slice(0, 16);
            }
            catch {
                continue;
            }
        }
    }
    return { pluginId: AGENT_AEGIS_PLUGIN_ID, stateDir: params.stateDir, rootDir, rootRealPath, protectedRoots: params.protectedRoots, fingerprints, updatedAt: Date.now() };
}
function createSyntheticSkillRiskState(params) {
    return { userRiskFlags: [], hasToolResult: false, toolResultRiskFlags: [], toolResultSuspicious: false, toolResultOversize: false, skillRiskFlags: [...params.skillRiskFlags], riskySkills: [...params.riskySkills], runtimeRiskFlags: [], prependNeeded: params.riskySkills.length > 0, updatedAt: params.now };
}
function joinPresentTextSegments(segments) {
    const values = segments.map((s) => s?.trim()).filter(Boolean);
    return values.length > 0 ? values.join("\n\n") : undefined;
}
function buildSecretFingerprints(values, source, timestamp) {
    return [...new Set(values.map((v) => v.trim()).filter(Boolean))].filter((v) => v.length >= 8).map((v) => ({ hash: createHash("sha256").update(v).digest("hex"), length: v.length, source, updatedAt: timestamp }));
}
function deriveScriptArtifactSignals(artifacts) {
    const sourceSignals = new Set();
    const transformSignals = new Set();
    const sinkSignals = new Set();
    const runtimeRiskFlags = new Set();
    for (const artifact of artifacts) {
        if (artifact.riskFlags.some((f) => f.includes("secret") || f.includes("sensitive")))
            sourceSignals.add("script-artifact");
        if (artifact.riskFlags.some((f) => f.includes("encoded") || f.includes("high-risk-command")))
            transformSignals.add("script-artifact");
        if (artifact.riskFlags.some((f) => f.includes("outbound-sink") || f.includes("exfiltration")))
            sinkSignals.add("script-artifact");
        for (const flag of artifact.riskFlags)
            runtimeRiskFlags.add(flag);
    }
    return { sourceSignals: [...sourceSignals], transformSignals: [...transformSignals], sinkSignals: [...sinkSignals], runtimeRiskFlags: [...runtimeRiskFlags] };
}
function readCommandText(params) {
    for (const key of ["command", "cmd", "code", "script"]) {
        const value = params[key];
        if (typeof value === "string" && value.trim())
            return value.trim();
    }
    return undefined;
}
