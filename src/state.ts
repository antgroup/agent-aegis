import { promises as fs } from "node:fs";
import path from "node:path";
import {
  LOOP_GUARD_TTL_MS,
  SELF_INTEGRITY_FILENAME,
  TRUSTED_SKILLS_FILENAME,
  TURN_STATE_TTL_MS,
} from "./config.js";
import type {
  AegisLogger,
  LoopCounterEntry,
  PromptSnapshot,
  RunSecuritySignalState,
  RunToolCallState,
  ScriptArtifactRecord,
  SecretFingerprintRecord,
  SkillAssessmentRecord,
  SelfIntegrityRecord,
  ToolCallRecord,
  ToolResultScanOutcome,
  TrustedSkillRecord,
  TurnSecurityState,
  WorkerHealthState,
} from "./types.js";

type PersistedTrustedSkillsFile = {
  version: 1;
  records: TrustedSkillRecord[];
};

type ObservedSecretEntry = {
  values: string[];
  updatedAt: number;
};

function createEmptyTurnState(now: number): TurnSecurityState {
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

function uniqueStrings(values: string[]): string[] {
  return [...new Set(values.filter((value) => value.trim().length > 0))];
}

function normalizePathKey(value: string): string {
  return path.resolve(value);
}

function deriveSkillIdFromPath(value: string): string {
  return path.basename(path.dirname(value));
}

async function readJsonFile<T>(filePath: string): Promise<T | null> {
  try {
    const raw = await fs.readFile(filePath, "utf8");
    return JSON.parse(raw) as T;
  } catch {
    return null;
  }
}

async function atomicWriteJson(filePath: string, value: unknown): Promise<void> {
  await fs.mkdir(path.dirname(filePath), { recursive: true });
  const tempPath = `${filePath}.${process.pid}.${Date.now()}.tmp`;
  try {
    await fs.writeFile(tempPath, `${JSON.stringify(value, null, 2)}\n`, "utf8");
    await fs.rename(tempPath, filePath);
  } finally {
    await fs.rm(tempPath, { force: true }).catch(() => undefined);
  }
}

function normalizeTrustedSkillsFile(raw: unknown): PersistedTrustedSkillsFile {
  const records = Array.isArray((raw as { records?: unknown })?.records)
    ? ((raw as { records: unknown[] }).records ?? [])
        .filter((entry): entry is TrustedSkillRecord => {
          return (
            typeof entry === "object" &&
            entry !== null &&
            typeof (entry as TrustedSkillRecord).path === "string" &&
            typeof (entry as TrustedSkillRecord).hash === "string" &&
            typeof (entry as TrustedSkillRecord).size === "number" &&
            typeof (entry as TrustedSkillRecord).scannedAt === "number"
          );
        })
        .map((entry) => ({
          ...entry,
          path: normalizePathKey(entry.path),
        }))
    : [];
  return { version: 1, records };
}

function normalizeSelfIntegrityRecord(raw: unknown): SelfIntegrityRecord | null {
  if (!raw || typeof raw !== "object") {
    return null;
  }
  const record = raw as Partial<SelfIntegrityRecord>;
  if (
    typeof record.pluginId !== "string" ||
    typeof record.stateDir !== "string" ||
    typeof record.updatedAt !== "number" ||
    !Array.isArray(record.protectedRoots) ||
    !record.fingerprints ||
    typeof record.fingerprints !== "object"
  ) {
    return null;
  }
  return {
    pluginId: record.pluginId,
    stateDir: record.stateDir,
    rootDir: typeof record.rootDir === "string" ? record.rootDir : undefined,
    rootRealPath: typeof record.rootRealPath === "string" ? record.rootRealPath : undefined,
    protectedRoots: record.protectedRoots
      .filter((entry): entry is string => typeof entry === "string")
      .map((entry) => normalizePathKey(entry)),
    fingerprints: Object.fromEntries(
      Object.entries(record.fingerprints).filter(([, value]) => typeof value === "string"),
    ) as Record<string, string>,
    updatedAt: record.updatedAt,
  };
}

export class AgentAegisState {
  private readonly turnStates = new Map<string, TurnSecurityState>();
  private readonly loopCounters = new Map<string, LoopCounterEntry>();
  private readonly sessionSecrets = new Map<string, ObservedSecretEntry>();
  private readonly sessionPrompts = new Map<string, PromptSnapshot>();
  private readonly lastUserInputs = new Map<string, { value: string; updatedAt: number }>();
  private readonly runToolCalls = new Map<string, RunToolCallState>();
  private readonly runSecuritySignals = new Map<string, RunSecuritySignalState>();
  private readonly trustedSkills = new Map<string, TrustedSkillRecord>();
  private readonly skillAssessments = new Map<string, SkillAssessmentRecord>();
  private protectedRoots: string[] = [];
  private selfIntegrityRecord: SelfIntegrityRecord | null = null;
  private workerHealthState: WorkerHealthState = {
    active: false,
    queueSize: 0,
    failureTimestamps: [],
  };

  constructor(
    private readonly params: {
      stateDir: string;
      logger: AegisLogger;
      now?: () => number;
    },
  ) {}

  private now(): number {
    return this.params.now?.() ?? Date.now();
  }

  private getTrustedSkillsPath(): string {
    return path.join(this.params.stateDir, TRUSTED_SKILLS_FILENAME);
  }

  private getSelfIntegrityPath(): string {
    return path.join(this.params.stateDir, SELF_INTEGRITY_FILENAME);
  }

  private cleanupExpiredState(now = this.now()): void {
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

  async loadPersistentState(): Promise<void> {
    const [trustedSkillsFile, selfIntegrityFile] = await Promise.all([
      readJsonFile<PersistedTrustedSkillsFile>(this.getTrustedSkillsPath()),
      readJsonFile<SelfIntegrityRecord>(this.getSelfIntegrityPath()),
    ]);

    const trustedSkills = normalizeTrustedSkillsFile(trustedSkillsFile);
    this.trustedSkills.clear();
    for (const record of trustedSkills.records) {
      this.trustedSkills.set(normalizePathKey(record.path), record);
    }

    this.selfIntegrityRecord = normalizeSelfIntegrityRecord(selfIntegrityFile);
  }

  async persistTrustedSkills(): Promise<void> {
    const records = [...this.trustedSkills.values()].sort((left, right) =>
      left.path.localeCompare(right.path),
    );
    await atomicWriteJson(this.getTrustedSkillsPath(), {
      version: 1,
      records,
    } satisfies PersistedTrustedSkillsFile);
  }

  async persistSelfIntegrity(): Promise<void> {
    if (!this.selfIntegrityRecord) {
      return;
    }
    await atomicWriteJson(this.getSelfIntegrityPath(), this.selfIntegrityRecord);
  }

  getStateDir(): string {
    return this.params.stateDir;
  }

  getSelfIntegrityRecord(): SelfIntegrityRecord | null {
    return this.selfIntegrityRecord;
  }

  setSelfIntegrityRecord(record: SelfIntegrityRecord): void {
    this.selfIntegrityRecord = record;
  }

  setProtectedRoots(roots: string[]): void {
    this.protectedRoots = uniqueStrings(roots.map((root) => normalizePathKey(root)));
  }

  getProtectedRoots(): string[] {
    return [...this.protectedRoots];
  }

  getTrustedSkill(pathValue: string, hash: string): TrustedSkillRecord | undefined {
    const record = this.trustedSkills.get(normalizePathKey(pathValue));
    if (!record || record.hash !== hash) {
      return undefined;
    }
    return record;
  }

  getSkillAssessment(pathValue: string, hash: string): SkillAssessmentRecord | undefined {
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

  rememberTrustedSkill(record: TrustedSkillRecord): void {
    this.trustedSkills.set(normalizePathKey(record.path), {
      ...record,
      path: normalizePathKey(record.path),
    });
  }

  rememberSkillAssessment(record: SkillAssessmentRecord): void {
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

  noteUserRisk(sessionKey: string, flags: string[]): TurnSecurityState {
    const now = this.now();
    this.cleanupExpiredState(now);
    const current = this.turnStates.get(sessionKey) ?? createEmptyTurnState(now);
    current.userRiskFlags = uniqueStrings([...current.userRiskFlags, ...flags]);
    current.prependNeeded = current.prependNeeded || current.userRiskFlags.length > 0;
    current.updatedAt = now;
    this.turnStates.set(sessionKey, current);
    return current;
  }

  noteToolResult(sessionKey: string, outcome: ToolResultScanOutcome): TurnSecurityState {
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

  noteSkillRisk(
    sessionKey: string,
    params: {
      flags: string[];
      skillIds: string[];
    },
  ): TurnSecurityState {
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

  noteRuntimeRisk(sessionKey: string, flags: string[]): TurnSecurityState {
    const now = this.now();
    this.cleanupExpiredState(now);
    const current = this.turnStates.get(sessionKey) ?? createEmptyTurnState(now);
    current.runtimeRiskFlags = uniqueStrings([...current.runtimeRiskFlags, ...flags]);
    current.prependNeeded = current.prependNeeded || current.runtimeRiskFlags.length > 0;
    current.updatedAt = now;
    this.turnStates.set(sessionKey, current);
    return current;
  }

  noteObservedSecrets(sessionKey: string, values: string[]): string[] {
    const now = this.now();
    this.cleanupExpiredState(now);
    const normalizedValues = uniqueStrings(values.map((value) => value.trim()).filter(Boolean)).sort(
      (left, right) => right.length - left.length || left.localeCompare(right),
    );
    const current = this.sessionSecrets.get(sessionKey);
    if (normalizedValues.length === 0) {
      if (current) {
        current.updatedAt = now;
      }
      return [...(current?.values ?? [])];
    }
    const nextValues = uniqueStrings([...(current?.values ?? []), ...normalizedValues]).sort(
      (left, right) => right.length - left.length || left.localeCompare(right),
    );
    this.sessionSecrets.set(sessionKey, {
      values: nextValues,
      updatedAt: now,
    });
    return [...nextValues];
  }

  peekObservedSecrets(sessionKey: string): string[] {
    const now = this.now();
    this.cleanupExpiredState(now);
    const entry = this.sessionSecrets.get(sessionKey);
    if (!entry) {
      return [];
    }
    entry.updatedAt = now;
    return [...entry.values];
  }

  notePromptSnapshot(sessionKey: string, prompt: string): PromptSnapshot {
    const now = this.now();
    this.cleanupExpiredState(now);
    const next = {
      prompt,
      updatedAt: now,
    } satisfies PromptSnapshot;
    this.sessionPrompts.set(sessionKey, next);
    return { ...next };
  }

  peekPromptSnapshot(sessionKey: string): PromptSnapshot | undefined {
    const now = this.now();
    this.cleanupExpiredState(now);
    const entry = this.sessionPrompts.get(sessionKey);
    if (!entry) {
      return undefined;
    }
    entry.updatedAt = now;
    return { ...entry };
  }

  noteLastUserInput(sessionKey: string, content: string): void {
    const now = this.now();
    this.cleanupExpiredState(now);
    this.lastUserInputs.set(sessionKey, {
      value: content.slice(0, 500),
      updatedAt: now,
    });
  }

  peekLastUserInput(sessionKey: string): string | undefined {
    const now = this.now();
    this.cleanupExpiredState(now);
    const entry = this.lastUserInputs.get(sessionKey);
    if (!entry) return undefined;
    entry.updatedAt = now;
    return entry.value;
  }

  noteRunToolCall(runId: string, record: ToolCallRecord): number {
    const now = this.now();
    this.cleanupExpiredState(now);
    const current = this.runToolCalls.get(runId);
    const nextEntry: RunToolCallState = {
      sessionKey: record.sessionKey ?? current?.sessionKey,
      calls: [...(current?.calls ?? []), { ...record, params: { ...record.params } }],
      updatedAt: now,
    };
    this.runToolCalls.set(runId, nextEntry);
    return nextEntry.calls.length;
  }

  private getOrCreateRunSecurityState(
    runId: string,
    sessionKey: string | undefined,
    now: number,
  ): RunSecuritySignalState {
    const current = this.runSecuritySignals.get(runId);
    if (current) {
      current.updatedAt = now;
      if (sessionKey && !current.sessionKey) {
        current.sessionKey = sessionKey;
      }
      return current;
    }
    const next: RunSecuritySignalState = {
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

  noteRunSecuritySignals(
    runId: string,
    params: {
      sessionKey?: string;
      sourceSignals?: string[];
      transformSignals?: string[];
      sinkSignals?: string[];
      runtimeRiskFlags?: string[];
    },
  ): RunSecuritySignalState {
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

  noteRunSecretFingerprints(
    runId: string,
    params: {
      sessionKey?: string;
      fingerprints: SecretFingerprintRecord[];
    },
  ): RunSecuritySignalState {
    const now = this.now();
    this.cleanupExpiredState(now);
    const state = this.getOrCreateRunSecurityState(runId, params.sessionKey, now);
    const existing = new Map<string, SecretFingerprintRecord>();
    for (const entry of state.secretFingerprints) {
      existing.set(`${entry.hash}:${entry.source}`, entry);
    }
    for (const fingerprint of params.fingerprints) {
      existing.set(`${fingerprint.hash}:${fingerprint.source}`, {
        ...fingerprint,
        updatedAt: now,
      });
    }
    state.secretFingerprints = [...existing.values()].sort((left, right) =>
      left.hash.localeCompare(right.hash),
    );
    state.updatedAt = now;
    return this.peekRunSecurityState(runId) ?? state;
  }

  noteRunScriptArtifacts(
    runId: string,
    params: {
      sessionKey?: string;
      artifacts: ScriptArtifactRecord[];
    },
  ): RunSecuritySignalState {
    const now = this.now();
    this.cleanupExpiredState(now);
    const state = this.getOrCreateRunSecurityState(runId, params.sessionKey, now);
    const existing = new Map<string, ScriptArtifactRecord>();
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
    state.scriptArtifacts = [...existing.values()].sort((left, right) =>
      left.path.localeCompare(right.path),
    );
    state.updatedAt = now;
    return this.peekRunSecurityState(runId) ?? state;
  }

  peekRunToolCalls(runId: string): ToolCallRecord[] {
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

  peekRunSecurityState(runId: string): RunSecuritySignalState | undefined {
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

  clearRunToolCalls(runId: string): void {
    this.runToolCalls.delete(runId);
  }

  clearRunSecurityState(runId: string): void {
    this.runSecuritySignals.delete(runId);
  }

  clearSessionRuntimeState(sessionKey: string): void {
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

  markToolResultSeen(sessionKey: string): TurnSecurityState {
    return this.noteToolResult(sessionKey, {
      hasToolResult: true,
      riskFlags: [],
      suspicious: false,
      oversize: false,
    });
  }

  consumePromptState(sessionKey: string): TurnSecurityState | undefined {
    const now = this.now();
    this.cleanupExpiredState(now);
    const state = this.turnStates.get(sessionKey);
    if (!state) {
      return undefined;
    }
    this.turnStates.delete(sessionKey);
    return state;
  }

  peekPromptState(sessionKey: string): TurnSecurityState | undefined {
    const now = this.now();
    this.cleanupExpiredState(now);
    return this.turnStates.get(sessionKey);
  }

  incrementLoopCounter(sessionKey: string, runId: string, stableArgsKey: string): number {
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

  setWorkerHealth(next: WorkerHealthState): void {
    this.workerHealthState = {
      ...next,
      failureTimestamps: [...next.failureTimestamps],
    };
  }

  getWorkerHealth(): WorkerHealthState {
    return {
      ...this.workerHealthState,
      failureTimestamps: [...this.workerHealthState.failureTimestamps],
    };
  }
}
