import type { AegisLogger, PromptSnapshot, RunSecuritySignalState, ScriptArtifactRecord, SecretFingerprintRecord, SkillAssessmentRecord, SelfIntegrityRecord, ToolCallRecord, ToolResultScanOutcome, TrustedSkillRecord, TurnSecurityState, WorkerHealthState } from "./types.js";
export declare class AgentAegisState {
    private readonly params;
    private readonly turnStates;
    private readonly loopCounters;
    private readonly sessionSecrets;
    private readonly sessionPrompts;
    private readonly lastUserInputs;
    private readonly runToolCalls;
    private readonly runSecuritySignals;
    private readonly trustedSkills;
    private readonly skillAssessments;
    private protectedRoots;
    private selfIntegrityRecord;
    private workerHealthState;
    constructor(params: {
        stateDir: string;
        logger: AegisLogger;
        now?: () => number;
    });
    private now;
    private getTrustedSkillsPath;
    private getSelfIntegrityPath;
    private cleanupExpiredState;
    loadPersistentState(): Promise<void>;
    persistTrustedSkills(): Promise<void>;
    persistSelfIntegrity(): Promise<void>;
    getStateDir(): string;
    getSelfIntegrityRecord(): SelfIntegrityRecord | null;
    setSelfIntegrityRecord(record: SelfIntegrityRecord): void;
    setProtectedRoots(roots: string[]): void;
    getProtectedRoots(): string[];
    getTrustedSkill(pathValue: string, hash: string): TrustedSkillRecord | undefined;
    getSkillAssessment(pathValue: string, hash: string): SkillAssessmentRecord | undefined;
    rememberTrustedSkill(record: TrustedSkillRecord): void;
    rememberSkillAssessment(record: SkillAssessmentRecord): void;
    noteUserRisk(sessionKey: string, flags: string[]): TurnSecurityState;
    noteToolResult(sessionKey: string, outcome: ToolResultScanOutcome): TurnSecurityState;
    noteSkillRisk(sessionKey: string, params: {
        flags: string[];
        skillIds: string[];
    }): TurnSecurityState;
    noteRuntimeRisk(sessionKey: string, flags: string[]): TurnSecurityState;
    noteObservedSecrets(sessionKey: string, values: string[]): string[];
    peekObservedSecrets(sessionKey: string): string[];
    notePromptSnapshot(sessionKey: string, prompt: string): PromptSnapshot;
    peekPromptSnapshot(sessionKey: string): PromptSnapshot | undefined;
    noteLastUserInput(sessionKey: string, content: string): void;
    peekLastUserInput(sessionKey: string): string | undefined;
    noteRunToolCall(runId: string, record: ToolCallRecord): number;
    private getOrCreateRunSecurityState;
    noteRunSecuritySignals(runId: string, params: {
        sessionKey?: string;
        sourceSignals?: string[];
        transformSignals?: string[];
        sinkSignals?: string[];
        runtimeRiskFlags?: string[];
    }): RunSecuritySignalState;
    noteRunSecretFingerprints(runId: string, params: {
        sessionKey?: string;
        fingerprints: SecretFingerprintRecord[];
    }): RunSecuritySignalState;
    noteRunScriptArtifacts(runId: string, params: {
        sessionKey?: string;
        artifacts: ScriptArtifactRecord[];
    }): RunSecuritySignalState;
    peekRunToolCalls(runId: string): ToolCallRecord[];
    peekRunSecurityState(runId: string): RunSecuritySignalState | undefined;
    clearRunToolCalls(runId: string): void;
    clearRunSecurityState(runId: string): void;
    clearSessionRuntimeState(sessionKey: string): void;
    markToolResultSeen(sessionKey: string): TurnSecurityState;
    consumePromptState(sessionKey: string): TurnSecurityState | undefined;
    peekPromptState(sessionKey: string): TurnSecurityState | undefined;
    incrementLoopCounter(sessionKey: string, runId: string, stableArgsKey: string): number;
    setWorkerHealth(next: WorkerHealthState): void;
    getWorkerHealth(): WorkerHealthState;
}
