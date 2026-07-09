import { ProbeEventBus } from "./channel/bus.js";
import {
  type AggregatedVerdict,
  type ProbeEvent,
  type Verdict,
} from "./channel/event.js";
import { EventQueue, type EventQueueOptions } from "./channel/event-queue.js";
import { EVENT_SCHEMA_VERSION, type AggregatorStrategy } from "./channel/schema.js";
import { ProbeEventStore } from "./channel/store.js";
import { SqliteEventIndex, type EventQuery, type EventRow } from "./channel/event-index.js";
import { AttributionEngine, type AttributionEngineOptions } from "./attribution/engine.js";
import { SessionEventBuffer, type SessionEventBufferOptions } from "./context/buffer.js";
import { aggregate, runJudges } from "./judges/aggregator.js";
import { type Judge, JudgeRegistry } from "./judges/base.js";
import type { Probe, ProbeDeps } from "./probes/types.js";
import { ResponsePolicyEngine, type ResponsePolicyConfig } from "./response/policy.js";
import type { AgentRuntime, ToolCallAttempt, VerdictApplication } from "./runtime/types.js";

export type { Judge } from "./judges/base.js";
export type { Probe, ProbeDeps } from "./probes/types.js";
export type { AgentRuntime } from "./runtime/types.js";
export type { ProbeEvent, Verdict, AggregatedVerdict } from "./channel/event.js";
export type { EventQueueOptions } from "./channel/event-queue.js";
export type { AttributionEngineOptions } from "./attribution/engine.js";
export type { SessionEventBufferOptions } from "./context/buffer.js";
export type { ResponsePolicyConfig } from "./response/policy.js";

export interface SentinelOptions {
  aggregatorStrategy?: AggregatorStrategy;
  /** Backpressure configuration for the probe→judge event queue (M10 P1.4). */
  eventQueue?: EventQueueOptions;
  /** Attribution engine configuration (M11). */
  attribution?: AttributionEngineOptions;
  /** Session context pipeline configuration (M11.5). */
  context?: { buffer?: SessionEventBufferOptions };
  /** Response ladder / policy engine configuration (M13). */
  response?: ResponsePolicyConfig;
}

/** Interval (ms) between drop-marker writes when events are being lost. */
const DROP_MARKER_INTERVAL_MS = 60_000;

export interface SentinelHandle {
  readonly runtime: AgentRuntime;
  registerJudge(judge: Judge): () => void;
  /**
   * Register and immediately start a probe. The promise resolves once the
   * probe's `start()` has returned (so callers can rely on the probe being
   * either live or having positively declined to run before the next line
   * executes). Probe failures are logged but do not throw — sentinel keeps
   * running with the remaining probes.
   */
  registerProbe(probe: Probe): Promise<void>;
  /**
   * Publish a probe event into the sentinel pipeline. Returns the aggregated
   * verdict (or null if no judges are registered / all abstained — caller
   * should treat null as "allow").
   */
  publish(event: ProbeEvent): Promise<AggregatedVerdict | null>;
  /**
   * Query the SQLite event index (newest-first). Returns [] when the index is
   * unavailable (e.g. Node < 22.5) — the JSONL log still has the full record.
   */
  queryEvents(query?: EventQuery): EventRow[];
  stop(): Promise<void>;
  /** Diagnostic snapshot — count of probes / judges currently attached plus queue stats. */
  status(): { judges: number; probes: number; queueDepth: number; dropped: number; sampled: number };
  /** Flush pending events through the pipeline (for tests / shutdown). */
  flush(): Promise<void>;
  /** The session event buffer (M11.5). Judges and adapters can read session context from this. */
  readonly contextBuffer: SessionEventBuffer;
}

/**
 * Start a sentinel instance bound to a given AgentRuntime.
 *
 * Sentinel itself is framework-agnostic; the runtime parameter is the only
 * surface through which framework-specific behavior leaks in.
 */
export function startSentinel(
  runtime: AgentRuntime,
  opts: SentinelOptions = {},
): SentinelHandle {
  const strategy: AggregatorStrategy = opts.aggregatorStrategy ?? "strictest";
  const logger = runtime.logger;

  const store = new ProbeEventStore({ stateDir: runtime.getStateDir() });
  const index = new SqliteEventIndex({ stateDir: runtime.getStateDir() });
  if (!index.available) {
    logger.warn(
      `[sentinel] queryable event index disabled (${index.unavailableReason ?? "node:sqlite unavailable"}); JSONL log unaffected`,
    );
  }
  const bus = new ProbeEventBus({
    onError: (err, event) =>
      logger.error(
        `[sentinel] subscriber threw for event ${event.id}: ${String(err)}`,
      ),
  });
  const registry = new JudgeRegistry();
  const probes: Probe[] = [];
  const verdictSubscribers = new Set<(v: AggregatedVerdict) => void>();
  const pendingProcessing: Promise<unknown>[] = [];
  const responsePolicy = new ResponsePolicyEngine({
    capabilities: runtime.capabilities,
    config: opts.response,
  });

  // --- Attribution engine (M11) ---
  // Enriches events with attribution, correlationId, and causal flags before
  // they reach the judge pipeline.
  const attributionEngine = new AttributionEngine(opts.attribution);
  // Seed with the runtime's known agent PIDs.
  try {
    const ctx = runtime.getCurrentContext();
    if (ctx.pids && ctx.pids.length > 0) {
      attributionEngine.seed(ctx.pids);
    }
  } catch {
    // getCurrentContext may not be available in all runtimes; continue without seeding.
  }

  // --- Session event buffer (M11.5) ---
  // Buffers enriched events per session for BehavioralSnapshot / AI context.
  const sessionEventBuffer = new SessionEventBuffer(opts.context?.buffer);

  // --- Event queue (P1.4 backpressure) ---
  // Probes produce events at kernel speed. The queue bounds memory and drops
  // with accounting when the pipeline can't keep up. The consumer persists to
  // JSONL/SQLite (so no accepted event is lost on disk) and fans out to the bus.
  const queue = new EventQueue(
    async (event) => {
      // 1) Persist first (durable log before judgment).
      try {
        store.appendEvent(event);
      } catch (err) {
        logger.error(`[sentinel] failed to persist event ${event.id}: ${String(err)}`);
      }
      try {
        index.appendEvent(event);
      } catch (err) {
        logger.error(`[sentinel] failed to index event ${event.id}: ${String(err)}`);
      }
      // 2) Fan out to bus subscribers (e.g. WebUI bridge).
      bus.publish(event);
      // 3) Run judge pipeline synchronously in the queue consumer.
      // This ensures flush() waits for the full pipeline.
      try {
        const p = processEvent(event);
        pendingProcessing.push(p);
        try {
          await p;
        } finally {
          const idx = pendingProcessing.indexOf(p);
          if (idx >= 0) pendingProcessing.splice(idx, 1);
        }
      } catch (err) {
        logger.error(`[sentinel] processEvent failed for ${event.id}: ${String(err)}`);
      }
    },
    {
      maxDepth: opts.eventQueue?.maxDepth ?? 4096,
      sampleRate: opts.eventQueue?.sampleRate ?? 1.0,
      onDrop: (count, reason) => {
        if (reason === "queue_full") {
          logger.warn(
            `[sentinel] event queue full; ${count} event(s) dropped (depth=${queue.size})`,
          );
        }
      },
    },
  );

  // Periodic drop-marker: write accumulated drop counts to the JSONL log.
  let dropMarkerTimer: ReturnType<typeof setInterval> | undefined;
  function flushDropMarker(): void {
    const { dropped, sampled } = queue.resetCounters();
    if (dropped > 0) store.appendDropMarker(dropped, "queue_full");
    if (sampled > 0) store.appendDropMarker(sampled, "sampled");
  }

  // Tool-call interceptor: wraps the runtime's tool-call attempt as a
  // synthetic ProbeEvent (source = "l1-hook"). These are low-volume and
  // latency-sensitive, so they bypass the queue and process synchronously.
  runtime.registerToolCallInterceptor(async (attempt) => {
    const event: ProbeEvent = {
      schema: EVENT_SCHEMA_VERSION,
      id: cryptoRandom(),
      timestamp: Date.now(),
      source: "l1-hook",
      syscall: "tool_call",
      pid: process.pid,
      args: { toolName: attempt.toolName, params: attempt.params },
      sessionKey: attempt.ctx.sessionKey,
      runId: attempt.ctx.runId,
      toolName: attempt.toolName,
      meta: attempt.ctx.meta,
    };
    // Tool-call events bypass the queue: persist + judge synchronously.
    try {
      store.appendEvent(event);
    } catch (err) {
      logger.error(`[sentinel] failed to persist tool-call event ${event.id}: ${String(err)}`);
    }
    try {
      index.appendEvent(event);
    } catch (err) {
      logger.error(`[sentinel] failed to index tool-call event ${event.id}: ${String(err)}`);
    }
    bus.publish(event);
    const aggregated = await processEvent(event);
    return toApplication(aggregated);
  });

  runtime.onShutdown(async () => {
    await handle.stop();
  });

  async function processEvent(event: ProbeEvent): Promise<AggregatedVerdict | null> {
    // M11: Enrich event with attribution, correlation, and causal chain data
    // before the judge pipeline runs. This mutates the event in place.
    attributionEngine.enrich(event);
    // M11.5: Buffer the enriched event for session-level context.
    // The buffer is available to future AI/rule judges via handle.contextBuffer.
    sessionEventBuffer.push(event);

    const judges = registry.list();
    if (judges.length === 0) {
      runtime.onSentinelEvent?.(event, null);
      return null;
    }
    const verdicts = await runJudges(judges, event, (judgeId, err) => {
      logger.warn(`[sentinel] judge ${judgeId} threw: ${String(err)}`);
    });
    const aggregated = responsePolicy.apply(event, aggregate(verdicts, strategy));
    try {
      store.appendVerdict(event.id, aggregated);
    } catch (err) {
      logger.error(`[sentinel] failed to persist verdict for ${event.id}: ${String(err)}`);
    }
    try {
      index.appendVerdict(event.id, aggregated);
    } catch (err) {
      logger.error(`[sentinel] failed to index verdict for ${event.id}: ${String(err)}`);
    }
    runtime.onSentinelEvent?.(event, aggregated);
    for (const cb of verdictSubscribers) {
      try {
        cb(aggregated);
      } catch (err) {
        logger.warn(`[sentinel] verdict subscriber threw: ${String(err)}`);
      }
    }
    return aggregated;
  }

  const probeDeps: ProbeDeps = {
    runtime,
    publish: async (event) => {
      // Probe events go through the bounded queue for backpressure.
      // Returns null because the verdict flows asynchronously through the
      // bus / onSentinelEvent — probes use fire-and-forget semantics.
      queue.enqueue(event);
      return null;
    },
    onVerdict: (cb) => {
      verdictSubscribers.add(cb);
      return () => {
        verdictSubscribers.delete(cb);
      };
    },
  };

  let stopped = false;
  const handle: SentinelHandle = {
    runtime,
    registerJudge: (judge) => {
      const unregister = registry.register(judge);
      logger.info(`[sentinel] judge registered: ${judge.id}`);
      return unregister;
    },
    registerProbe: async (probe) => {
      try {
        await probe.start(probeDeps);
        probes.push(probe);
        logger.info(`[sentinel] probe registered: ${probe.id}`);
      } catch (err) {
        logger.warn(
          `[sentinel] probe ${probe.id} failed to start; continuing without it: ${String(err)}`,
        );
      }
    },
    publish: async (event) => {
      // Direct publish (handle-level) also goes through the queue.
      queue.enqueue(event);
      return null;
    },
    queryEvents: (query) => index.query(query),
    stop: async () => {
      if (stopped) return;
      stopped = true;
      // Flush any pending events in the queue before shutting down.
      await queue.flush();
      flushDropMarker();
      if (dropMarkerTimer !== undefined) {
        clearInterval(dropMarkerTimer);
      }
      for (const probe of probes) {
        try {
          await probe.stop();
        } catch (err) {
          logger.warn(`[sentinel] probe ${probe.id} stop threw: ${String(err)}`);
        }
      }
      probes.length = 0;
      bus.clear();
      await store.close();
      index.close();
    },
    status: () => ({
      judges: registry.size(),
      probes: probes.length,
      queueDepth: queue.size,
      dropped: queue.dropped,
      sampled: queue.sampled,
    }),
    flush: async () => {
      await queue.flush();
      // Wait for any pending async processEvent calls to finish.
      // This ensures that after flush(), verdicts are written to the store.
      const pending = [...pendingProcessing];
      if (pending.length > 0) {
        await Promise.all(pending);
      }
      flushDropMarker();
    },
    contextBuffer: sessionEventBuffer,
  };

  // Start the periodic drop-marker + buffer prune timer.
  dropMarkerTimer = setInterval(() => {
    flushDropMarker();
    sessionEventBuffer.prune();
  }, DROP_MARKER_INTERVAL_MS);
  // Don't let the timer prevent process exit.
  if (dropMarkerTimer && typeof dropMarkerTimer === "object" && "unref" in dropMarkerTimer) {
    (dropMarkerTimer as ReturnType<typeof setInterval> & { unref(): void }).unref();
  }

  logger.info(
    `[agent-aegis] sentinel core constructed (strategy=${strategy}, runtime=${runtime.name}, queueDepth=${opts.eventQueue?.maxDepth ?? 4096}, sampleRate=${opts.eventQueue?.sampleRate ?? 1.0}); judges/probes register next`,
  );
  return handle;
}

function toApplication(aggregated: AggregatedVerdict | null): VerdictApplication {
  if (!aggregated) {
    return {
      block: false,
      aggregated: {
        final: {
          action: "allow",
          severity: "info",
          reason: "no judges registered",
          judgeId: "sentinel:no-judges",
          confidence: 1,
        },
        sources: [],
      },
    };
  }
  const v: Verdict = aggregated.final;
  return {
    block: v.action === "block",
    reason: v.reason,
    aggregated,
  };
}

function cryptoRandom(): string {
  // Local fallback in case of frozen-time test environments; real events go
  // through createProbeEvent() which uses node:crypto.randomUUID.
  return `evt-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}

// silence unused import for ToolCallAttempt — referenced only in TS types
export type { ToolCallAttempt };
