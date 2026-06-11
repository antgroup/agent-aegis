export type AegisLogger = {
    debug?: (message: string, meta?: Record<string, unknown>) => void;
    info: (message: string, meta?: Record<string, unknown>) => void;
    warn: (message: string, meta?: Record<string, unknown>) => void;
    error: (message: string, meta?: Record<string, unknown>) => void;
};
export type TurnSecurityState = {
    userRiskFlags: string[];
    hasToolResult: boolean;
    toolResultRiskFlags: string[];
    toolResultSuspicious: boolean;
    toolResultOversize: boolean;
    skillRiskFlags: string[];
    riskySkills: string[];
    runtimeRiskFlags: string[];
    prependNeeded: boolean;
    updatedAt: number;
};
export type SkillAssessmentRecord = {
    path: string;
    hash: string;
    size: number;
    trusted: boolean;
    findings: string[];
    skillId: string;
    sourceRoot?: string;
    scannedAt: number;
};
export type TrustedSkillRecord = {
    path: string;
    hash: string;
    size: number;
    sourceRoot?: string;
    scannedAt: number;
};
export type SelfIntegrityRecord = {
    pluginId: string;
    stateDir: string;
    rootDir?: string;
    rootRealPath?: string;
    protectedRoots: string[];
    fingerprints: Record<string, string>;
    updatedAt: number;
};
export type LoopCounterEntry = {
    count: number;
    updatedAt: number;
};
export type PromptSnapshot = {
    prompt: string;
    updatedAt: number;
};
export type ToolCallRecord = {
    runId: string;
    sessionKey?: string;
    toolName: string;
    params: Record<string, unknown>;
    timestamp: number;
    blocked?: boolean;
    blockReason?: string;
};
export type SecretFingerprintRecord = {
    hash: string;
    length: number;
    source: string;
    updatedAt: number;
};
export type ScriptArtifactRecord = {
    path: string;
    hash: string;
    size: number;
    sourceTool: string;
    sessionKey?: string;
    runId: string;
    riskFlags: string[];
    updatedAt: number;
};
export type RunToolCallState = {
    sessionKey?: string;
    calls: ToolCallRecord[];
    updatedAt: number;
};
export type RunSecuritySignalState = {
    sessionKey?: string;
    sourceSignals: string[];
    transformSignals: string[];
    sinkSignals: string[];
    runtimeRiskFlags: string[];
    secretFingerprints: SecretFingerprintRecord[];
    scriptArtifacts: ScriptArtifactRecord[];
    updatedAt: number;
};
export type WorkerHealthState = {
    active: boolean;
    queueSize: number;
    failureTimestamps: number[];
    cooldownUntil?: number;
};
export type ToolResultScanOutcome = {
    hasToolResult: boolean;
    riskFlags: string[];
    suspicious: boolean;
    oversize: boolean;
};
export type UserRiskMatch = {
    flags: string[];
};
export type SkillScanRequest = {
    requestId: string;
    path: string;
    hash: string;
    size: number;
    sourceRoot?: string;
    text: string;
};
export type SkillScanResult = {
    trusted: boolean;
    findings: string[];
};
export type SkillRiskReview = {
    reviewedCount: number;
    rescannedCount: number;
    reusedCount: number;
    riskyAssessments: SkillAssessmentRecord[];
};
export type SkillScanJobResult = {
    status: "queued";
} | {
    status: "already-trusted";
} | {
    status: "already-reviewed";
} | {
    status: "skipped-backpressure";
} | {
    status: "skipped-cooldown";
};
