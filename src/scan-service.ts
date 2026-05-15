import { createHash } from "node:crypto";
import type { Dirent } from "node:fs";
import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { Worker } from "node:worker_threads";
import {
  SKILL_SCAN_COOLDOWN_MS,
  SKILL_SCAN_FAILURE_THRESHOLD,
  SKILL_SCAN_FAILURE_WINDOW_MS,
  SKILL_SCAN_FILE_MAX_BYTES,
  SKILL_SCAN_QUEUE_MAX,
  SKILL_SCAN_TARGET_FILENAME,
  SKILL_SCAN_ALLOWED_EXTENSIONS,
  SKILL_SCAN_TIMEOUT_MS,
} from "./config.js";
import { scanSkillText } from "./scan-worker.js";
import { ClawAegisState } from "./state.js";
import type {
  AegisLogger,
  SkillAssessmentRecord,
  SkillScanJobResult,
  SkillScanRequest,
  SkillRiskReview,
  SkillScanResult,
} from "./types.js";

type PendingWorkerRequest = {
  resolve: (value: SkillScanResult) => void;
  reject: (error: unknown) => void;
  timeout: ReturnType<typeof setTimeout>;
  request: SkillScanRequest;
  startedAt: number;
  phase: "execution" | "turn_review";
};

type SkillScanLogMeta = {
  phase: "roots" | "queue" | "execution" | "turn_review";
  durationMs?: number;
  result?: string;
  [key: string]: unknown;
};

type PreparedSkillFile = {
  path: string;
  hash: string;
  size: number;
  sourceRoot?: string;
  text: string;
  skillId: string;
};

function normalizeSkillId(value: string | undefined, fallbackPath: string): string {
  const trimmed = value?.trim().replace(/^['"]|['"]$/g, "");
  if (trimmed) return trimmed;
  
  const dirname = path.basename(path.dirname(fallbackPath));
  if (dirname === "skills" || dirname === "workspace") {
    // If it's in a generic directory, use the filename without extension
    return path.parse(fallbackPath).name;
  }
  return dirname;
}

function extractSkillId(filePath: string, text: string): string {
  const frontmatterMatch = text.match(/^---\s*\n([\s\S]*?)\n---(?:\n|$)/);
  if (!frontmatterMatch) {
    return normalizeSkillId(undefined, filePath);
  }
  const nameMatch = frontmatterMatch[1]?.match(/^\s*name\s*:\s*(.+)\s*$/m);
  return normalizeSkillId(nameMatch?.[1], filePath);
}

export class SkillScanService {
  private readonly queue: SkillScanRequest[] = [];
  private readonly queuedKeys = new Set<string>();
  private readonly pendingWorkerRequests = new Map<string, PendingWorkerRequest>();
  private active = false;
  private stopped = false;
  private requestCounter = 0;
  private failureTimestamps: number[] = [];
  private cooldownUntil: number | undefined;
  private worker: Worker | null = null;
  private workerSupported = true;
  private lastPendingWorkerFailure:
    | {
        reason: string;
        timestamp: number;
      }
    | undefined;

  constructor(
    private readonly params: {
      state: ClawAegisState;
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
    },
  ) {}

  private now(): number {
    return this.params.now?.() ?? Date.now();
  }

  private syncWorkerHealth(): void {
    this.params.state.setWorkerHealth({
      active: this.active,
      queueSize: this.queue.length,
      failureTimestamps: [...this.failureTimestamps],
      cooldownUntil: this.cooldownUntil,
    });
  }

  private pruneFailures(now = this.now()): void {
    this.failureTimestamps = this.failureTimestamps.filter(
      (timestamp) => now - timestamp <= SKILL_SCAN_FAILURE_WINDOW_MS,
    );
  }

  private isCooldownActive(now = this.now()): boolean {
    return Boolean(this.cooldownUntil && this.cooldownUntil > now);
  }

  private logSkillScanStart(meta: SkillScanLogMeta): void {
    this.params.logger.info("claw-aegis: 开始执行 skill 扫描", {
      event: "skill_scan_started",
      ...meta,
    });
  }

  private logSkillScanFinish(meta: SkillScanLogMeta): void {
    this.params.logger.info("claw-aegis: skill 扫描结束", {
      event: "skill_scan_finished",
      ...meta,
    });
  }

  private logSkillScanResult(meta: SkillScanLogMeta, level: "info" | "warn" = "info"): void {
    const message = "claw-aegis: skill 扫描结果";
    const payload = {
      event: "skill_scan_result",
      ...meta,
    };
    if (level === "warn") {
      this.params.logger.warn(message, payload);
      return;
    }
    this.params.logger.info(message, payload);
  }

  private normalizeRoots(roots: string[]): string[] {
    return [
      ...new Set(
        roots
          .map((root) => {
            const trimmed = root.trim();
            if (trimmed.startsWith("~")) {
              return path.join(os.homedir(), trimmed.slice(1));
            }
            return path.resolve(trimmed);
          })
          .filter(Boolean),
      ),
    ];
  }

  private buildAssessment(
    request: SkillScanRequest,
    result: SkillScanResult,
    skillId: string,
  ): SkillAssessmentRecord {
    return {
      path: request.path,
      hash: request.hash,
      size: request.size,
      trusted: result.trusted,
      findings: result.findings,
      skillId,
      sourceRoot: request.sourceRoot,
      scannedAt: this.now(),
    };
  }

  private rememberPendingWorkerFailure(reason: string): void {
    this.lastPendingWorkerFailure = {
      reason,
      timestamp: this.now(),
    };
  }

  private shouldSuppressWorkerFailure(reason: string): boolean {
    if (!this.lastPendingWorkerFailure) {
      return false;
    }
    return (
      this.lastPendingWorkerFailure.reason === reason &&
      this.now() - this.lastPendingWorkerFailure.timestamp <= 1000
    );
  }

  private fallbackToInlineScan(reason: string): void {
    if (!this.workerSupported) {
      return;
    }
    this.workerSupported = false;
    this.params.logger.warn("claw-aegis: 已回退到内联 skill 扫描", {
      event: "skill_worker_fallback",
      reason,
    });
  }

  private async walkSkillFiles(
    root: string,
    visitor: (filePath: string, sourceRoot: string) => Promise<void>,
    deadline = Number.POSITIVE_INFINITY,
  ): Promise<void> {
    const stack = [root];
    while (stack.length > 0) {
      if (this.now() > deadline) {
        return;
      }
      const current = stack.pop();
      if (!current) {
        continue;
      }
      let entries: Dirent[];
      try {
        entries = await fs.readdir(current, { withFileTypes: true });
      } catch {
        continue;
      }
      for (const entry of entries) {
        if (this.now() > deadline) {
          return;
        }
        if (entry.name === "node_modules" || entry.name === ".git") {
          continue;
        }
        const absolutePath = path.join(current, entry.name);
        if (entry.isDirectory()) {
          stack.push(absolutePath);
          continue;
        }
        if (!entry.isFile()) {
          continue;
        }
        const ext = path.extname(entry.name).toLowerCase();
        if (entry.name !== SKILL_SCAN_TARGET_FILENAME && !SKILL_SCAN_ALLOWED_EXTENSIONS.includes(ext)) {
          continue;
        }
        await visitor(absolutePath, root);
      }
    }
  }

  private recordFailure(error: unknown, meta?: Record<string, unknown>): void {
    const now = this.now();
    this.pruneFailures(now);
    this.failureTimestamps.push(now);
    if (this.failureTimestamps.length >= SKILL_SCAN_FAILURE_THRESHOLD) {
      this.cooldownUntil = now + SKILL_SCAN_COOLDOWN_MS;
    }
    this.syncWorkerHealth();
    this.params.logger.warn("claw-aegis: skill 扫描已降级", {
      event: "skill_scan_failure",
      reason: error instanceof Error ? error.message : String(error),
      crashCount: this.failureTimestamps.length,
      cooldownUntil: this.cooldownUntil,
      ...meta,
    });
  }

  private clearCooldownIfElapsed(): void {
    const now = this.now();
    if (this.cooldownUntil && this.cooldownUntil <= now) {
      this.cooldownUntil = undefined;
      this.pruneFailures(now);
      this.syncWorkerHealth();
    }
  }

  start(): void {
    this.stopped = false;
    this.clearCooldownIfElapsed();
    this.syncWorkerHealth();
    this.params.logger.info("claw-aegis: skill 扫描服务已就绪", {
      event: "skill_scan_service_ready",
    });
  }

  async stop(): Promise<void> {
    this.stopped = true;
    for (const [, pending] of this.pendingWorkerRequests) {
      clearTimeout(pending.timeout);
      pending.reject(new Error("技能扫描服务已停止"));
    }
    this.pendingWorkerRequests.clear();
    this.queue.length = 0;
    this.queuedKeys.clear();
    const worker = this.worker;
    this.worker = null;
    this.active = false;
    this.syncWorkerHealth();
    if (worker) {
      await worker.terminate().catch(() => undefined);
    }
  }

  async scanRoots(params: { roots: string[]; budgetMs?: number }): Promise<void> {
    const startedAt = this.now();
    this.logSkillScanStart({
      phase: "roots",
      rootCount: params.roots.length,
      budgetMs: params.budgetMs,
    });
    if (this.stopped) {
      const durationMs = this.now() - startedAt;
      this.logSkillScanResult({
        phase: "roots",
        result: "stopped",
        rootCount: params.roots.length,
        budgetMs: params.budgetMs,
        durationMs,
      });
      this.logSkillScanFinish({
        phase: "roots",
        result: "stopped",
        rootCount: params.roots.length,
        budgetMs: params.budgetMs,
        durationMs,
      });
      return;
    }
    this.clearCooldownIfElapsed();
    const deadline = Number.isFinite(params.budgetMs ?? Infinity)
      ? this.now() + Number(params.budgetMs)
      : Number.POSITIVE_INFINITY;
    const roots = this.normalizeRoots(params.roots);
    for (const root of roots) {
      if (this.now() > deadline) {
        break;
      }
      await this.scanRoot(root, deadline);
    }
    const durationMs = this.now() - startedAt;
    this.logSkillScanResult({
      phase: "roots",
      result: this.now() > deadline ? "budget_exhausted" : "completed",
      rootCount: roots.length,
      budgetMs: params.budgetMs,
      durationMs,
    });
    this.logSkillScanFinish({
      phase: "roots",
      result: this.now() > deadline ? "budget_exhausted" : "completed",
      rootCount: roots.length,
      budgetMs: params.budgetMs,
      durationMs,
    });
  }

  private async scanRoot(root: string, deadline: number): Promise<void> {
    await this.walkSkillFiles(
      root,
      async (filePath, sourceRoot) => {
        await this.enqueueFile(filePath, sourceRoot);
      },
      deadline,
    );
  }

  async inspectTurnSkillRisks(params: { roots: string[] }): Promise<SkillRiskReview> {
    const startedAt = this.now();
    const roots = this.normalizeRoots(params.roots);
    const riskyAssessments: SkillAssessmentRecord[] = [];
    let reviewedCount = 0;
    let rescannedCount = 0;
    let reusedCount = 0;
    let persistTrustedSkillsNeeded = false;
    let hadErrors = false;
    let skippedCooldownCount = 0;

    this.logSkillScanStart({
      phase: "turn_review",
      rootCount: roots.length,
    });

    for (const root of roots) {
      await this.walkSkillFiles(root, async (filePath, sourceRoot) => {
        const prepared = await this.prepareSkillFile(filePath, sourceRoot);
        if (!prepared) {
          return;
        }
        reviewedCount += 1;
        const cached = this.params.state.getSkillAssessment(prepared.path, prepared.hash);
        if (cached) {
          reusedCount += 1;
          if (!cached.trusted) {
            riskyAssessments.push(cached);
          }
          return;
        }

        this.clearCooldownIfElapsed();
        if (this.isCooldownActive()) {
          skippedCooldownCount += 1;
          this.params.logger.warn("claw-aegis: 冷却期间已跳过本轮 skill 扫描", {
            event: "skill_scan_skipped",
            phase: "turn_review",
            state: "cooldown",
            path: prepared.path,
          });
          return;
        }

        rescannedCount += 1;
        const request: SkillScanRequest = {
          requestId: `turn-scan-${++this.requestCounter}`,
          path: prepared.path,
          hash: prepared.hash,
          size: prepared.size,
          sourceRoot: prepared.sourceRoot,
          text: prepared.text,
        };

        try {
          const result = await this.executeScan(request, "turn_review");
          const assessment = this.buildAssessment(request, result, prepared.skillId);
          this.params.state.rememberSkillAssessment(assessment);
          this.emitScanComplete(assessment, "turn_review");
          if (assessment.trusted) {
            persistTrustedSkillsNeeded = true;
            return;
          }
          riskyAssessments.push(assessment);
        } catch (error) {
          hadErrors = true;
          this.recordFailure(error, {
            event: "skill_scan_error",
            phase: "turn_review",
            path: prepared.path,
          });
        }
      });
    }

    if (persistTrustedSkillsNeeded) {
      try {
        await this.params.state.persistTrustedSkills();
      } catch (error) {
        hadErrors = true;
        this.params.logger.error("claw-aegis: 持久化 trusted skill 缓存失败", {
          event: "skill_scan_persist_failed",
          phase: "turn_review",
          reason: error instanceof Error ? error.message : String(error),
        });
      }
    }

    const durationMs = this.now() - startedAt;
    const result =
      riskyAssessments.length > 0
        ? "risk_detected"
        : hadErrors
          ? "completed_with_errors"
          : skippedCooldownCount > 0
            ? "completed_with_cooldown"
            : "clear";
    if (riskyAssessments.length > 0) {
      this.params.logger.warn("claw-aegis: 检测到高风险 skill", {
        event: "skill_risk_detected",
        phase: "turn_review",
        riskySkillCount: riskyAssessments.length,
        riskySkills: riskyAssessments.map((assessment) => assessment.skillId),
        findings: [...new Set(riskyAssessments.flatMap((assessment) => assessment.findings))],
        reviewedCount,
        rescannedCount,
        reusedCount,
        durationMs,
      });
    }
    this.logSkillScanResult({
      phase: "turn_review",
      result,
      reviewedCount,
      rescannedCount,
      reusedCount,
      skippedCooldownCount,
      riskySkillCount: riskyAssessments.length,
      durationMs,
    });
    this.logSkillScanFinish({
      phase: "turn_review",
      result,
      reviewedCount,
      rescannedCount,
      reusedCount,
      skippedCooldownCount,
      riskySkillCount: riskyAssessments.length,
      durationMs,
    });

    return {
      reviewedCount,
      rescannedCount,
      reusedCount,
      riskyAssessments,
    };
  }

  private async prepareSkillFile(
    filePath: string,
    sourceRoot: string,
  ): Promise<PreparedSkillFile | null> {
    const filename = path.basename(filePath);
    const ext = path.extname(filename).toLowerCase();
    if (filename !== SKILL_SCAN_TARGET_FILENAME && !SKILL_SCAN_ALLOWED_EXTENSIONS.includes(ext)) {
      return null;
    }

    let stat: Awaited<ReturnType<typeof fs.stat>>;
    try {
      stat = await fs.stat(filePath);
    } catch {
      return null;
    }
    if (stat.size > SKILL_SCAN_FILE_MAX_BYTES) {
      return null;
    }

    let text: string;
    try {
      text = await fs.readFile(filePath, "utf8");
    } catch {
      return null;
    }
    if (text.includes("\0")) {
      return null;
    }

    const resolvedPath = path.resolve(filePath);
    return {
      path: resolvedPath,
      hash: this.hashText(text),
      size: stat.size,
      sourceRoot,
      text,
      skillId: extractSkillId(resolvedPath, text),
    };
  }

  private async enqueueFile(filePath: string, sourceRoot: string): Promise<SkillScanJobResult> {
    const startedAt = this.now();
    this.logSkillScanStart({
      phase: "queue",
      path: filePath,
      sourceRoot,
    });
    this.clearCooldownIfElapsed();
    if (this.isCooldownActive()) {
      const durationMs = this.now() - startedAt;
      this.params.logger.warn("claw-aegis: 冷却期间已跳过 skill 扫描", {
        event: "skill_scan_skipped",
        state: "cooldown",
        path: filePath,
        durationMs,
      });
      this.logSkillScanFinish({
        phase: "queue",
        path: filePath,
        sourceRoot,
        result: "skipped_cooldown",
        durationMs,
      });
      return { status: "skipped-cooldown" };
    }
    if (path.basename(filePath) !== SKILL_SCAN_TARGET_FILENAME) {
      const durationMs = this.now() - startedAt;
      this.logSkillScanResult({
        phase: "queue",
        path: filePath,
        sourceRoot,
        result: "ignored_non_skill_file",
        durationMs,
      });
      this.logSkillScanFinish({
        phase: "queue",
        path: filePath,
        sourceRoot,
        result: "ignored_non_skill_file",
        durationMs,
      });
      return { status: "already-reviewed" };
    }

    let prepared: PreparedSkillFile | null;
    try {
      prepared = await this.prepareSkillFile(filePath, sourceRoot);
    } catch {
      prepared = null;
    }
    if (!prepared) {
      const durationMs = this.now() - startedAt;
      this.logSkillScanResult({
        phase: "queue",
        path: filePath,
        sourceRoot,
        result: "ignored_unreadable",
        durationMs,
      });
      this.logSkillScanFinish({
        phase: "queue",
        path: filePath,
        sourceRoot,
        result: "ignored_unreadable",
        durationMs,
      });
      return { status: "already-reviewed" };
    }

    const cachedAssessment = this.params.state.getSkillAssessment(prepared.path, prepared.hash);
    if (cachedAssessment?.trusted) {
      const durationMs = this.now() - startedAt;
      this.logSkillScanResult({
        phase: "queue",
        path: prepared.path,
        sourceRoot,
        result: "already_trusted",
        durationMs,
        hash: prepared.hash,
      });
      this.logSkillScanFinish({
        phase: "queue",
        path: prepared.path,
        sourceRoot,
        result: "already_trusted",
        durationMs,
        hash: prepared.hash,
      });
      return { status: "already-trusted" };
    }
    if (cachedAssessment) {
      const durationMs = this.now() - startedAt;
      this.logSkillScanResult({
        phase: "queue",
        path: prepared.path,
        sourceRoot,
        result: "already_reviewed_risky",
        durationMs,
        hash: prepared.hash,
        skillId: cachedAssessment.skillId,
      });
      this.logSkillScanFinish({
        phase: "queue",
        path: prepared.path,
        sourceRoot,
        result: "already_reviewed_risky",
        durationMs,
        hash: prepared.hash,
        skillId: cachedAssessment.skillId,
      });
      return { status: "already-reviewed" };
    }
    const queueKey = `${prepared.path}|${prepared.hash}`;
    if (this.queuedKeys.has(queueKey)) {
      const durationMs = this.now() - startedAt;
      this.logSkillScanResult({
        phase: "queue",
        path: prepared.path,
        sourceRoot,
        result: "already_queued",
        durationMs,
        hash: prepared.hash,
      });
      this.logSkillScanFinish({
        phase: "queue",
        path: prepared.path,
        sourceRoot,
        result: "already_queued",
        durationMs,
        hash: prepared.hash,
      });
      return { status: "queued" };
    }
    if (this.queue.length >= SKILL_SCAN_QUEUE_MAX) {
      const durationMs = this.now() - startedAt;
      this.params.logger.warn("claw-aegis: 由于背压已跳过 skill 扫描", {
        event: "skill_scan_backpressure",
        path: filePath,
        state: "scanSkippedDueToBackpressure",
        durationMs,
      });
      this.logSkillScanFinish({
        phase: "queue",
        path: filePath,
        sourceRoot,
        result: "skipped_backpressure",
        durationMs,
      });
      return { status: "skipped-backpressure" };
    }

    const request: SkillScanRequest = {
      requestId: `scan-${++this.requestCounter}`,
      path: prepared.path,
      hash: prepared.hash,
      size: prepared.size,
      sourceRoot,
      text: prepared.text,
    };
    this.queue.push(request);
    this.queuedKeys.add(queueKey);
    this.syncWorkerHealth();
    const durationMs = this.now() - startedAt;
    this.logSkillScanResult({
      phase: "queue",
      path: request.path,
      sourceRoot,
      result: "queued",
      durationMs,
      hash: prepared.hash,
      size: prepared.size,
      queueSize: this.queue.length,
      skillId: prepared.skillId,
    });
    this.logSkillScanFinish({
      phase: "queue",
      path: request.path,
      sourceRoot,
      result: "queued",
      durationMs,
      hash: prepared.hash,
      size: prepared.size,
      queueSize: this.queue.length,
      skillId: prepared.skillId,
    });
    void this.processNext();
    return { status: "queued" };
  }

  private emitScanComplete(assessment: SkillAssessmentRecord, phase: string): void {
    this.params.onScanComplete?.({
      timestamp: assessment.scannedAt,
      skillId: assessment.skillId,
      path: assessment.path,
      hash: assessment.hash,
      size: assessment.size,
      sourceRoot: assessment.sourceRoot,
      trusted: assessment.trusted,
      findings: assessment.findings,
      phase,
    });
  }

  private hashText(text: string): string {
    return createHash("sha256").update(text).digest("hex");
  }

  private async processNext(): Promise<void> {
    if (this.active || this.stopped) {
      return;
    }
    this.clearCooldownIfElapsed();
    if (this.isCooldownActive()) {
      this.queue.length = 0;
      this.queuedKeys.clear();
      this.syncWorkerHealth();
      return;
    }
    const next = this.queue.shift();
    if (!next) {
      this.syncWorkerHealth();
      return;
    }

    const startedAt = this.now();
    this.logSkillScanStart({
      phase: "execution",
      path: next.path,
      requestId: next.requestId,
      sourceRoot: next.sourceRoot,
    });
    this.active = true;
    this.syncWorkerHealth();
    try {
      const result = await this.executeScan(next, "execution");
      const durationMs = this.now() - startedAt;
      const assessment = this.buildAssessment(next, result, extractSkillId(next.path, next.text));
      this.params.state.rememberSkillAssessment(assessment);
      this.emitScanComplete(assessment, "startup");
      if (assessment.trusted) {
        await this.params.state.persistTrustedSkills();
      }
      this.params.logger.debug?.("claw-aegis: 已完成 skill 扫描", {
        event: "skill_scan_complete",
        path: next.path,
        trusted: result.trusted,
        findingCount: result.findings.length,
        durationMs,
      });
      this.logSkillScanFinish({
        phase: "execution",
        path: next.path,
        requestId: next.requestId,
        sourceRoot: next.sourceRoot,
        result: result.trusted ? "trusted" : "risky",
        durationMs,
        findingCount: result.findings.length,
        skillId: assessment.skillId,
      });
    } catch (error) {
      const durationMs = this.now() - startedAt;
      this.recordFailure(error, {
        event: "skill_scan_error",
        path: next.path,
        durationMs,
      });
      this.logSkillScanFinish({
        phase: "execution",
        path: next.path,
        requestId: next.requestId,
        sourceRoot: next.sourceRoot,
        result: "error",
        durationMs,
      });
    } finally {
      this.queuedKeys.delete(`${next.path}|${next.hash}`);
      this.active = false;
      this.syncWorkerHealth();
      if (this.queue.length > 0) {
        void this.processNext();
      }
    }
  }

  private async executeScan(
    request: SkillScanRequest,
    phase: "execution" | "turn_review",
  ): Promise<SkillScanResult> {
    const startedAt = this.now();
    if (this.params.runner) {
      const result = await this.params.runner(request);
      const durationMs = this.now() - startedAt;
      this.logSkillScanResult({
        phase,
        path: request.path,
        requestId: request.requestId,
        sourceRoot: request.sourceRoot,
        result: result.trusted ? "trusted" : "risky",
        durationMs,
        findingCount: result.findings.length,
        executionMode: "runner",
      });
      return result;
    }
    const worker = await this.ensureWorker();
    if (!worker) {
      const result = scanSkillText(request.text);
      const durationMs = this.now() - startedAt;
      this.logSkillScanResult({
        phase,
        path: request.path,
        requestId: request.requestId,
        sourceRoot: request.sourceRoot,
        result: result.trusted ? "trusted" : "risky",
        durationMs,
        findingCount: result.findings.length,
        executionMode: "inline",
      });
      return result;
    }

    return await new Promise<SkillScanResult>((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingWorkerRequests.delete(request.requestId);
        this.worker = null;
        void worker.terminate().catch(() => undefined);
        reject(new Error("技能扫描超时"));
      }, SKILL_SCAN_TIMEOUT_MS);

      this.pendingWorkerRequests.set(request.requestId, {
        resolve,
        reject,
        timeout,
        request,
        startedAt,
        phase,
      });

      try {
        worker.postMessage(request);
      } catch (error) {
        clearTimeout(timeout);
        this.pendingWorkerRequests.delete(request.requestId);
        reject(error);
      }
    });
  }

  private async ensureWorker(): Promise<Worker | null> {
    if (!this.workerSupported) {
      return null;
    }
    if (this.worker) {
      return this.worker;
    }

    try {
      const workerUrl = new URL("./scan-worker.js", import.meta.url);
      await fs.access(fileURLToPath(workerUrl));
      const worker = new Worker(workerUrl, { type: "module" } as WorkerOptions);
      worker.on(
        "message",
        (message: { requestId?: string; result?: SkillScanResult; error?: string }) => {
          const requestId = typeof message.requestId === "string" ? message.requestId : "";
          if (!requestId) {
            return;
          }
          const pending = this.pendingWorkerRequests.get(requestId);
          if (!pending) {
            return;
          }
          clearTimeout(pending.timeout);
          this.pendingWorkerRequests.delete(requestId);
          if (message.error) {
            pending.reject(new Error(message.error));
            return;
          }
          const result = message.result ?? {
            trusted: false,
            findings: ["invalid-worker-response"],
          };
          this.logSkillScanResult({
            phase: pending.phase,
            path: pending.request.path,
            requestId: pending.request.requestId,
            sourceRoot: pending.request.sourceRoot,
            result: result.trusted ? "trusted" : "risky",
            durationMs: this.now() - pending.startedAt,
            findingCount: result.findings.length,
            executionMode: "worker",
          });
          pending.resolve(result);
        },
      );
      worker.on("error", (error) => {
        const rejectedCount = this.failPendingWorkerRequests(error);
        this.worker = null;
        const reason = error instanceof Error ? error.message : String(error);
        this.fallbackToInlineScan(reason);
        if (rejectedCount > 0) {
          this.rememberPendingWorkerFailure(reason);
          return;
        }
        if (!this.shouldSuppressWorkerFailure(reason)) {
          this.recordFailure(error, { event: "skill_worker_error" });
        }
      });
      worker.on("exit", (code) => {
        const exitingWorker = this.worker;
        this.worker = null;
        if (this.stopped || code === 0) {
          return;
        }
        const error = new Error(`skill worker 退出，退出码为 ${code}`);
        const rejectedCount = this.failPendingWorkerRequests(error);
        this.fallbackToInlineScan(error.message);
        if (rejectedCount > 0) {
          this.rememberPendingWorkerFailure(error.message);
          return;
        }
        if (exitingWorker && !this.shouldSuppressWorkerFailure(error.message)) {
          this.recordFailure(error, { event: "skill_worker_exit", code });
        }
      });
      this.worker = worker;
      this.params.logger.info("claw-aegis: skill worker 已启动", {
        event: "skill_worker_started",
      });
      return worker;
    } catch (error) {
      this.fallbackToInlineScan(error instanceof Error ? error.message : String(error));
      return null;
    }
  }

  private failPendingWorkerRequests(error: unknown): number {
    let rejectedCount = 0;
    for (const [, pending] of this.pendingWorkerRequests) {
      clearTimeout(pending.timeout);
      pending.reject(error);
      rejectedCount += 1;
    }
    this.pendingWorkerRequests.clear();
    return rejectedCount;
  }
}
