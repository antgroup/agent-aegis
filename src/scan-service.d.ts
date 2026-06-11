import { AgentAegisState } from "./state.js";
import type { AegisLogger, SkillScanRequest, SkillRiskReview, SkillScanResult } from "./types.js";
export declare class SkillScanService {
    private readonly params;
    private readonly queue;
    private readonly queuedKeys;
    private readonly pendingWorkerRequests;
    private active;
    private stopped;
    private requestCounter;
    private failureTimestamps;
    private cooldownUntil;
    private worker;
    private workerSupported;
    private lastPendingWorkerFailure;
    constructor(params: {
        state: AgentAegisState;
        logger: AegisLogger;
        now?: () => number;
        runner?: (request: SkillScanRequest) => Promise<SkillScanResult>;
        onScanComplete?: (record: {
            timestamp: number;
            skillId: string;
            path: string;
            hash: string;
            size: number;
            sourceRoot?: string;
            trusted: boolean;
            findings: string[];
            phase: string;
        }) => void;
    });
    private now;
    private syncWorkerHealth;
    private pruneFailures;
    private isCooldownActive;
    private logSkillScanStart;
    private logSkillScanFinish;
    private logSkillScanResult;
    private normalizeRoots;
    private buildAssessment;
    private rememberPendingWorkerFailure;
    private shouldSuppressWorkerFailure;
    private fallbackToInlineScan;
    private walkSkillFiles;
    private recordFailure;
    private clearCooldownIfElapsed;
    start(): void;
    stop(): Promise<void>;
    scanRoots(params: {
        roots: string[];
        budgetMs?: number;
    }): Promise<void>;
    private scanRoot;
    inspectTurnSkillRisks(params: {
        roots: string[];
    }): Promise<SkillRiskReview>;
    private prepareSkillFile;
    private enqueueFile;
    private emitScanComplete;
    private hashText;
    private processNext;
    private executeScan;
    private ensureWorker;
    private failPendingWorkerRequests;
}
