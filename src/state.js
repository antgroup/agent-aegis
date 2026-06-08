import { promises as fs } from "node:fs";
import path from "node:path";
import { LOOP_GUARD_TTL_MS, SELF_INTEGRITY_FILENAME, TRUSTED_SKILLS_FILENAME, TURN_STATE_TTL_MS, } from "./config.js";
function createEmptyTurnState(now) {
    return {
        userRiskFlags: [],
        hasToolResult: false,
        toolResultRiskFlags: [],
        toolResultSuspicious: false,
        toolResultOversize: false,
        skillRiskFlags: [],
        riskySkills: [],
        runtimeRiskFlags: [],
        prependNeeded: false,
        updatedAt: now,
    };
}
function uniqueStrings(values) {
    return [...new Set(values.filter((value) => value.trim().length > 0))];
}
function normalizePathKey(value) {
    return path.resolve(value);
}
function deriveSkillIdFromPath(value) {
    return path.basename(path.dirname(value));
}
async function readJsonFile(filePath) {
    try {
        const raw = await fs.readFile(filePath, "utf8");
        return JSON.parse(raw);
    }
    catch {
        return null;
    }
}
async function atomicWriteJson(filePath, value) {
    await fs.mkdir(path.dirname(filePath), { recursive: true });
    const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
    try {
        await fs.writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
        await fs.rename(tempPath, filePath);
    }
    finally {
        await fs.rm(tempPath, { force: true }).catch(() => undefined);
    }
}
function normalizeTrustedSkillsFile(raw) {
    const records = Array.isArray(raw?.records)
        ? (raw.records ?? [])
            .filter((entry) => {
            return (typeof entry === "object" &&
                entry !== null &&
                typeof entry.path === "string" &&
                typeof entry.hash === "string" &&
                typeof entry.size === "number" &&
                typeof entry.scannedAt === "number");
        })
            .map((entry) => ({
            ...entry,
            path: normalizePathKey(entry.path),
        }))
        : [];
    return { version: 1, records };
}
function normalizeSelfIntegrityRecord(raw) {
    if (!raw || typeof raw !== "object") {
        return null;
    }
    const record = raw;
    if (typeof record.pluginId !== "string" ||
        typeof record.stateDir !== "string" ||
        typeof record.updatedAt !== "number" ||
        !Array.isArray(record.protectedRoots) ||
        !record.fingerprints ||
        typeof record.fingerprints !== "object") {
        return null;
    }
    return {
        pluginId: record.pluginId,
        stateDir: record.stateDir,
        rootDir: typeof record.rootDir === "string" ? record.rootDir : undefined,
        rootRealPath: typeof record.rootRealPath === "string" ? record.rootRealPath : undefined,
        protectedRoots: record.protectedRoots
            .filter((entry) => typeof entry === "string")
            .map((entry) => normalizePathKey(entry)),
        fingerprints: Object.fromEntries(Object.entries(record.fingerprints).filter(([, value]) => typeof value === "string")),
        updatedAt: record.updatedAt,
    };
}
export class AgentAegisState {
    params;
    turnStates = new Map();
    loopCounters = new Map();
    sessionSecrets = new Map();
    sessionPrompts = new Map();
    lastUserInputs = new Map();
    runToolCalls = new Map();
    runSecuritySignals = new Map();
    trustedSkills = new Map();
    skillAssessments = new Map();
    protectedRoots = [];
    selfIntegrityRecord = null;
    workerHealthState = {
        active: false,
        queueSize: 0,
        failureTimestamps: [],
    };
    constructor(params) {
        this.params = params;
    }
    now() {
        return this.params.now?.() ?? Date.now();
    }
    getTrustedSkillsPath() {
        return path.join(this.params.stateDir, TRUSTED_SKILLS_FILENAME);
    }
    getSelfIntegrityPath() {
        return path.join(this.params.stateDir, SELF_INTEGRITY_FILENAME);
    }
    cleanupExpiredState(now = this.now()) {
        for (const [sessionKey, entry] of this.turnStates) {
            if (now - entry.updatedAt > TURN_STATE_TTL_MS) {
                this.turnStates.delete(sessionKey);
            }
        }
        for (const [loopKey, entry] of this.loopCounters) {
            if (now - entry.updatedAt > LOOP_GUARD_TTL_MS) {
                this.loopCounters.delete(loopKey);
            }
        }
        for (const [sessionKey, entry] of this.sessionSecrets) {
            if (now - entry.updatedAt > TURN_STATE_TTL_MS) {
                this.sessionSecrets.delete(sessionKey);
            }
        }
        for (const [sessionKey, entry] of this.sessionPrompts) {
            if (now - entry.updatedAt > TURN_STATE_TTL_MS) {
                this.sessionPrompts.delete(sessionKey);
            }
        }
        for (const [sessionKey, entry] of this.lastUserInputs) {
            if (now - entry.updatedAt > TURN_STATE_TTL_MS) {
                this.lastUserInputs.delete(sessionKey);
            }
        }
        for (const [runId, entry] of this.runToolCalls) {
            if (now - entry.updatedAt > TURN_STATE_TTL_MS) {
                this.runToolCalls.delete(runId);
            }
        }
        for (const [runId, entry] of this.runSecuritySignals) {
            if (now - entry.updatedAt > TURN_STATE_TTL_MS) {
                this.runSecuritySignals.delete(runId);
            }
        }
    }
    async loadPersistentState() {
        const [trustedSkillsFile, selfIntegrityFile] = await Promise.all([
            readJsonFile(this.getTrustedSkillsPath()),
            readJsonFile(this.getSelfIntegrityPath()),
        ]);
        const trustedSkills = normalizeTrustedSkillsFile(trustedSkillsFile);
        this.trustedSkills.clear();
        for (const record of trustedSkills.records) {
            this.trustedSkills.set(normalizePathKey(record.path), record);
        }
        this.selfIntegrityRecord = normalizeSelfIntegrityRecord(selfIntegrityFile);
    }
    async persistTrustedSkills() {
        const records = [...this.trustedSkills.values()].sort((left, right) => left.path.localeCompare(right.path));
        await atomicWriteJson(this.getTrustedSkillsPath(), {
            version: 1,
            records,
        });
    }
    async persistSelfIntegrity() {
        if (!this.selfIntegrityRecord) {
            return;
        }
        await atomicWriteJson(this.getSelfIntegrityPath(), this.selfIntegrityRecord);
    }
    getStateDir() {
        return this.params.stateDir;
    }
    getSelfIntegrityRecord() {
        return this.selfIntegrityRecord;
    }
    setSelfIntegrityRecord(record) {
        this.selfIntegrityRecord = record;
    }
    setProtectedRoots(roots) {
        this.protectedRoots = uniqueStrings(roots.map((root) => normalizePathKey(root)));
    }
    getProtectedRoots() {
        return [...this.protectedRoots];
    }
    getTrustedSkill(pathValue, hash) {
        const record = this.trustedSkills.get(normalizePathKey(pathValue));
        if (!record || record.hash !== hash) {
            return undefined;
        }
        return record;
    }
    getSkillAssessment(pathValue, hash) {
        const pathKey = normalizePathKey(pathValue);
        const record = this.skillAssessments.get(pathKey);
        if (record && record.hash === hash) {
            return {
                ...record,
                findings: [...record.findings],
            };
        }
        const trustedRecord = this.trustedSkills.get(pathKey);
        if (!trustedRecord || trustedRecord.hash !== hash) {
            return undefined;
        }
        return {
            ...trustedRecord,
            trusted: true,
            findings: [],
            skillId: deriveSkillIdFromPath(trustedRecord.path),
        };
    }
    rememberTrustedSkill(record) {
        this.trustedSkills.set(normalizePathKey(record.path), {
            ...record,
            path: normalizePathKey(record.path),
        });
    }
    rememberSkillAssessment(record) {
        const normalizedPath = normalizePathKey(record.path);
        const normalizedRecord = {
            ...record,
            path: normalizedPath,
            findings: uniqueStrings(record.findings),
            skillId: record.skillId.trim() || deriveSkillIdFromPath(normalizedPath),
        };
        this.skillAssessments.set(normalizedPath, normalizedRecord);
        if (normalizedRecord.trusted) {
            this.rememberTrustedSkill({
                path: normalizedRecord.path,
                hash: normalizedRecord.hash,
                size: normalizedRecord.size,
                sourceRoot: normalizedRecord.sourceRoot,
                scannedAt: normalizedRecord.scannedAt,
            });
        }
    }
    noteUserRisk(sessionKey, flags) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const current = this.turnStates.get(sessionKey) ?? createEmptyTurnState(now);
        current.userRiskFlags = uniqueStrings([...current.userRiskFlags, ...flags]);
        current.prependNeeded = current.prependNeeded || current.userRiskFlags.length > 0;
        current.updatedAt = now;
        this.turnStates.set(sessionKey, current);
        return current;
    }
    noteToolResult(sessionKey, outcome) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const current = this.turnStates.get(sessionKey) ?? createEmptyTurnState(now);
        current.hasToolResult = outcome.hasToolResult || current.hasToolResult;
        current.toolResultRiskFlags = uniqueStrings([
            ...current.toolResultRiskFlags,
            ...outcome.riskFlags,
        ]);
        current.toolResultSuspicious = current.toolResultSuspicious || outcome.suspicious;
        current.toolResultOversize = current.toolResultOversize || outcome.oversize;
        current.prependNeeded = current.prependNeeded || current.hasToolResult;
        current.updatedAt = now;
        this.turnStates.set(sessionKey, current);
        return current;
    }
    noteSkillRisk(sessionKey, params) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const current = this.turnStates.get(sessionKey) ?? createEmptyTurnState(now);
        current.skillRiskFlags = uniqueStrings([...current.skillRiskFlags, ...params.flags]);
        current.riskySkills = uniqueStrings([...current.riskySkills, ...params.skillIds]);
        current.prependNeeded = current.prependNeeded || current.riskySkills.length > 0;
        current.updatedAt = now;
        this.turnStates.set(sessionKey, current);
        return current;
    }
    noteRuntimeRisk(sessionKey, flags) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const current = this.turnStates.get(sessionKey) ?? createEmptyTurnState(now);
        current.runtimeRiskFlags = uniqueStrings([...current.runtimeRiskFlags, ...flags]);
        current.prependNeeded = current.prependNeeded || current.runtimeRiskFlags.length > 0;
        current.updatedAt = now;
        this.turnStates.set(sessionKey, current);
        return current;
    }
    noteObservedSecrets(sessionKey, values) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const normalizedValues = uniqueStrings(values.map((value) => value.trim()).filter(Boolean)).sort((left, right) => right.length - left.length || left.localeCompare(right));
        const current = this.sessionSecrets.get(sessionKey);
        if (normalizedValues.length === 0) {
            if (current) {
                current.updatedAt = now;
            }
            return [...(current?.values ?? [])];
        }
        const nextValues = uniqueStrings([...(current?.values ?? []), ...normalizedValues]).sort((left, right) => right.length - left.length || left.localeCompare(right));
        this.sessionSecrets.set(sessionKey, {
            values: nextValues,
            updatedAt: now,
        });
        return [...nextValues];
    }
    peekObservedSecrets(sessionKey) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const entry = this.sessionSecrets.get(sessionKey);
        if (!entry) {
            return [];
        }
        entry.updatedAt = now;
        return [...entry.values];
    }
    notePromptSnapshot(sessionKey, prompt) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const next = {
            prompt,
            updatedAt: now,
        };
        this.sessionPrompts.set(sessionKey, next);
        return { ...next };
    }
    peekPromptSnapshot(sessionKey) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const entry = this.sessionPrompts.get(sessionKey);
        if (!entry) {
            return undefined;
        }
        entry.updatedAt = now;
        return { ...entry };
    }
    noteLastUserInput(sessionKey, content) {
        const now = this.now();
        this.cleanupExpiredState(now);
        this.lastUserInputs.set(sessionKey, {
            value: content.slice(0, 500),
            updatedAt: now,
        });
    }
    peekLastUserInput(sessionKey) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const entry = this.lastUserInputs.get(sessionKey);
        if (!entry)
            return undefined;
        entry.updatedAt = now;
        return entry.value;
    }
    noteRunToolCall(runId, record) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const current = this.runToolCalls.get(runId);
        const nextEntry = {
            sessionKey: record.sessionKey ?? current?.sessionKey,
            calls: [...(current?.calls ?? []), { ...record, params: { ...record.params } }],
            updatedAt: now,
        };
        this.runToolCalls.set(runId, nextEntry);
        return nextEntry.calls.length;
    }
    getOrCreateRunSecurityState(runId, sessionKey, now) {
        const current = this.runSecuritySignals.get(runId);
        if (current) {
            current.updatedAt = now;
            if (sessionKey && !current.sessionKey) {
                current.sessionKey = sessionKey;
            }
            return current;
        }
        const next = {
            sessionKey,
            sourceSignals: [],
            transformSignals: [],
            sinkSignals: [],
            runtimeRiskFlags: [],
            secretFingerprints: [],
            scriptArtifacts: [],
            updatedAt: now,
        };
        this.runSecuritySignals.set(runId, next);
        return next;
    }
    noteRunSecuritySignals(runId, params) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const state = this.getOrCreateRunSecurityState(runId, params.sessionKey, now);
        state.sourceSignals = uniqueStrings([...state.sourceSignals, ...(params.sourceSignals ?? [])]);
        state.transformSignals = uniqueStrings([
            ...state.transformSignals,
            ...(params.transformSignals ?? []),
        ]);
        state.sinkSignals = uniqueStrings([...state.sinkSignals, ...(params.sinkSignals ?? [])]);
        state.runtimeRiskFlags = uniqueStrings([
            ...state.runtimeRiskFlags,
            ...(params.runtimeRiskFlags ?? []),
        ]);
        state.updatedAt = now;
        return {
            ...state,
            sourceSignals: [...state.sourceSignals],
            transformSignals: [...state.transformSignals],
            sinkSignals: [...state.sinkSignals],
            runtimeRiskFlags: [...state.runtimeRiskFlags],
            secretFingerprints: state.secretFingerprints.map((entry) => ({ ...entry })),
            scriptArtifacts: state.scriptArtifacts.map((entry) => ({ ...entry, riskFlags: [...entry.riskFlags] })),
        };
    }
    noteRunSecretFingerprints(runId, params) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const state = this.getOrCreateRunSecurityState(runId, params.sessionKey, now);
        const existing = new Map();
        for (const entry of state.secretFingerprints) {
            existing.set(`${entry.hash}:${entry.source}`, entry);
        }
        for (const fingerprint of params.fingerprints) {
            existing.set(`${fingerprint.hash}:${fingerprint.source}`, {
                ...fingerprint,
                updatedAt: now,
            });
        }
        state.secretFingerprints = [...existing.values()].sort((left, right) => left.hash.localeCompare(right.hash));
        state.updatedAt = now;
        return this.peekRunSecurityState(runId) ?? state;
    }
    noteRunScriptArtifacts(runId, params) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const state = this.getOrCreateRunSecurityState(runId, params.sessionKey, now);
        const existing = new Map();
        for (const artifact of state.scriptArtifacts) {
            existing.set(artifact.path, artifact);
        }
        for (const artifact of params.artifacts) {
            existing.set(artifact.path, {
                ...artifact,
                riskFlags: uniqueStrings(artifact.riskFlags),
                updatedAt: now,
            });
        }
        state.scriptArtifacts = [...existing.values()].sort((left, right) => left.path.localeCompare(right.path));
        state.updatedAt = now;
        return this.peekRunSecurityState(runId) ?? state;
    }
    peekRunToolCalls(runId) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const entry = this.runToolCalls.get(runId);
        if (!entry) {
            return [];
        }
        entry.updatedAt = now;
        return entry.calls.map((call) => ({
            ...call,
            params: { ...call.params },
        }));
    }
    peekRunSecurityState(runId) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const entry = this.runSecuritySignals.get(runId);
        if (!entry) {
            return undefined;
        }
        entry.updatedAt = now;
        return {
            ...entry,
            sourceSignals: [...entry.sourceSignals],
            transformSignals: [...entry.transformSignals],
            sinkSignals: [...entry.sinkSignals],
            runtimeRiskFlags: [...entry.runtimeRiskFlags],
            secretFingerprints: entry.secretFingerprints.map((fingerprint) => ({ ...fingerprint })),
            scriptArtifacts: entry.scriptArtifacts.map((artifact) => ({
                ...artifact,
                riskFlags: [...artifact.riskFlags],
            })),
        };
    }
    clearRunToolCalls(runId) {
        this.runToolCalls.delete(runId);
    }
    clearRunSecurityState(runId) {
        this.runSecuritySignals.delete(runId);
    }
    clearSessionRuntimeState(sessionKey) {
        this.turnStates.delete(sessionKey);
        this.sessionSecrets.delete(sessionKey);
        this.sessionPrompts.delete(sessionKey);
        for (const [loopKey] of this.loopCounters) {
            if (loopKey.startsWith(`${sessionKey}|`)) {
                this.loopCounters.delete(loopKey);
            }
        }
        for (const [runId, entry] of this.runToolCalls) {
            if (entry.sessionKey === sessionKey) {
                this.runToolCalls.delete(runId);
            }
        }
        for (const [runId, entry] of this.runSecuritySignals) {
            if (entry.sessionKey === sessionKey) {
                this.runSecuritySignals.delete(runId);
            }
        }
    }
    markToolResultSeen(sessionKey) {
        return this.noteToolResult(sessionKey, {
            hasToolResult: true,
            riskFlags: [],
            suspicious: false,
            oversize: false,
        });
    }
    consumePromptState(sessionKey) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const state = this.turnStates.get(sessionKey);
        if (!state) {
            return undefined;
        }
        this.turnStates.delete(sessionKey);
        return state;
    }
    peekPromptState(sessionKey) {
        const now = this.now();
        this.cleanupExpiredState(now);
        return this.turnStates.get(sessionKey);
    }
    incrementLoopCounter(sessionKey, runId, stableArgsKey) {
        const now = this.now();
        this.cleanupExpiredState(now);
        const counterKey = `${sessionKey}|${runId}|${stableArgsKey}`;
        const current = this.loopCounters.get(counterKey);
        const nextCount = (current?.count ?? 0) + 1;
        this.loopCounters.set(counterKey, {
            count: nextCount,
            updatedAt: now,
        });
        return nextCount;
    }
    setWorkerHealth(next) {
        this.workerHealthState = {
            ...next,
            failureTimestamps: [...next.failureTimestamps],
        };
    }
    getWorkerHealth() {
        return {
            ...this.workerHealthState,
            failureTimestamps: [...this.workerHealthState.failureTimestamps],
        };
    }
}
