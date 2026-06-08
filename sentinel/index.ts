import { ProbeEventBus } from "./channel/bus.js";
import {
  type AggregatedVerdict,
  type ProbeEvent,
  type Verdict,
} from "./channel/event.js";
import type { AggregatorStrategy } from "./channel/schema.js";
import { ProbeEventStore } from "./channel/store.js";
import { aggregate, runJudges } from "./judges/aggregator.js";
import { type Judge, JudgeRegistry } from "./judges/base.js";
import type { Probe, ProbeDeps } from "./probes/types.js";
import type { AgentRuntime, ToolCallAttempt, VerdictApplication } from "./runtime/types.js";

export type { Judge } from "./judges/base.js";
export type { Probe, ProbeDeps } from "./probes/types.js";
export type { AgentRuntime } from "./runtime/types.js";
export type { ProbeEvent, Verdict, AggregatedVerdict } from "./channel/event.js";

export interface SentinelOptions {
  aggregatorStrategy?: AggregatorStrategy;
}

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
  stop(): Promise<void>;
  /** Diagnostic snapshot — count of probes / judges currently attached. */
  status(): { judges: number; probes: number };
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
  const bus = new ProbeEventBus({
    onError: (err, event) =>
      logger.error(
        `[sentinel] subscriber threw for event ${event.id}: ${String(err)}`,
      ),
  });
  const registry = new JudgeRegistry();
  const probes: Probe[] = [];
  const verdictSubscribers = new Set<(v: AggregatedVerdict) => void>();

  // Persistence subscriber: every published event lands in JSONL.
  bus.subscribe((event) => {
    try {
      store.appendEvent(event);
    } catch (err) {
      logger.error(`[sentinel] failed to persist event ${event.id}: ${String(err)}`);
    }
  });

  // Tool-call interceptor: wraps the runtime's tool-call attempt as a
  // synthetic ProbeEvent (source = "l1-hook") so that the same judge
  // pipeline applies to high-level intercepts and low-level probes.
  runtime.registerToolCallInterceptor(async (attempt) => {
    const event: ProbeEvent = {
      schema: 1,
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
    bus.publish(event);
    const aggregated = await processEvent(event);
    return toApplication(aggregated);
  });

  runtime.onShutdown(async () => {
    await handle.stop();
  });

  async function processEvent(event: ProbeEvent): Promise<AggregatedVerdict | null> {
    const judges = registry.list();
    if (judges.length === 0) {
      runtime.onSentinelEvent?.(event, null);
      return null;
    }
    const verdicts = await runJudges(judges, event, (judgeId, err) => {
      logger.warn(`[sentinel] judge ${judgeId} threw: ${String(err)}`);
    });
    const aggregated = aggregate(verdicts, strategy);
    try {
      store.appendVerdict(event.id, aggregated);
    } catch (err) {
      logger.error(`[sentinel] failed to persist verdict for ${event.id}: ${String(err)}`);
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
      bus.publish(event);
      return processEvent(event);
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
      bus.publish(event);
      return processEvent(event);
    },
    stop: async () => {
      if (stopped) return;
      stopped = true;
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
    },
    status: () => ({ judges: registry.size(), probes: probes.length }),
  };

  logger.info(
    `[agent-aegis] sentinel core constructed (strategy=${strategy}, runtime=${runtime.name}); judges/probes register next`,
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
