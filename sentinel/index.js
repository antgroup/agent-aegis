import { ProbeEventBus } from "./channel/bus.js";
import { ProbeEventStore } from "./channel/store.js";
import { aggregate, runJudges } from "./judges/aggregator.js";
import { JudgeRegistry } from "./judges/base.js";
/**
 * Start a sentinel instance bound to a given AgentRuntime.
 *
 * Sentinel itself is framework-agnostic; the runtime parameter is the only
 * surface through which framework-specific behavior leaks in.
 */
export function startSentinel(runtime, opts = {}) {
    const strategy = opts.aggregatorStrategy ?? "strictest";
    const logger = runtime.logger;
    const store = new ProbeEventStore({ stateDir: runtime.getStateDir() });
    const bus = new ProbeEventBus({
        onError: (err, event) => logger.error(`[sentinel] subscriber threw for event ${event.id}: ${String(err)}`),
    });
    const registry = new JudgeRegistry();
    const probes = [];
    const verdictSubscribers = new Set();
    // Persistence subscriber: every published event lands in JSONL.
    bus.subscribe((event) => {
        try {
            store.appendEvent(event);
        }
        catch (err) {
            logger.error(`[sentinel] failed to persist event ${event.id}: ${String(err)}`);
        }
    });
    // Tool-call interceptor: wraps the runtime's tool-call attempt as a
    // synthetic ProbeEvent (source = "l1-hook") so that the same judge
    // pipeline applies to high-level intercepts and low-level probes.
    runtime.registerToolCallInterceptor(async (attempt) => {
        const event = {
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
    async function processEvent(event) {
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
        }
        catch (err) {
            logger.error(`[sentinel] failed to persist verdict for ${event.id}: ${String(err)}`);
        }
        runtime.onSentinelEvent?.(event, aggregated);
        for (const cb of verdictSubscribers) {
            try {
                cb(aggregated);
            }
            catch (err) {
                logger.warn(`[sentinel] verdict subscriber threw: ${String(err)}`);
            }
        }
        return aggregated;
    }
    const probeDeps = {
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
    const handle = {
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
            }
            catch (err) {
                logger.warn(`[sentinel] probe ${probe.id} failed to start; continuing without it: ${String(err)}`);
            }
        },
        publish: async (event) => {
            bus.publish(event);
            return processEvent(event);
        },
        stop: async () => {
            if (stopped)
                return;
            stopped = true;
            for (const probe of probes) {
                try {
                    await probe.stop();
                }
                catch (err) {
                    logger.warn(`[sentinel] probe ${probe.id} stop threw: ${String(err)}`);
                }
            }
            probes.length = 0;
            bus.clear();
            await store.close();
        },
        status: () => ({ judges: registry.size(), probes: probes.length }),
    };
    logger.info(`[claw-aegis] sentinel core constructed (strategy=${strategy}, runtime=${runtime.name}); judges/probes register next`);
    return handle;
}
function toApplication(aggregated) {
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
    const v = aggregated.final;
    return {
        block: v.action === "block",
        reason: v.reason,
        aggregated,
    };
}
function cryptoRandom() {
    // Local fallback in case of frozen-time test environments; real events go
    // through createProbeEvent() which uses node:crypto.randomUUID.
    return `evt-${Date.now()}-${Math.random().toString(36).slice(2, 10)}`;
}
