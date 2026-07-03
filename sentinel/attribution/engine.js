import { ProcessTree } from "./process-tree.js";
import { CorrelationWindow } from "./correlation.js";
import { CausalChainDetector } from "./causal-chain.js";
/**
 * AttributionEngine enriches probe events with attribution, correlation,
 * and causal chain information (M11).
 *
 * It sits before the judge pipeline in `processEvent()`, populating:
 * - `event.meta.attribution`: "agent" | "descendant" | "external"
 * - `event.correlationId`: links syscalls to the tool call that likely caused them
 * - `event.parentEventId`: links lifecycle fork/exec events to their parent process
 * - `event.meta.causalFlags`: detected attack patterns like ["exfil", "write_then_run"]
 */
export class AttributionEngine {
    tree;
    correlator;
    causal;
    pruneCounter = 0;
    pruneInterval = 100; // Prune every N events
    constructor(opts = {}) {
        this.tree = new ProcessTree({
            maxNodes: opts.maxTreeNodes,
            staleMs: opts.staleNodeMs,
            pruneMs: opts.pruneNodeMs,
        });
        this.correlator = new CorrelationWindow({
            windowMs: opts.correlationWindowMs,
        });
        this.causal = new CausalChainDetector({
            windowMs: opts.causalWindowMs,
            maxPerSession: opts.maxCausalPerSession,
        });
    }
    /**
     * Seed the process tree with the known agent PID(s).
     * Call this once at startup with `runtime.getCurrentContext().pids`.
     */
    seed(pids) {
        this.tree.seed(pids);
    }
    /**
     * Enrich a probe event with attribution data.
     *
     * This modifies the event in place:
     * - Sets `meta.attribution` based on the process tree
     * - Sets `correlationId` if the event correlates with an open tool-call window
     * - Sets `meta.causalFlags` if attack patterns are detected
     * - For lifecycle fork/exec events, sets `parentEventId` to the parent's last event
     *
     * Also updates the internal state (process tree, correlation windows, causal windows).
     */
    enrich(event) {
        // Step 1: Update process tree based on event type.
        this.updateTree(event);
        // Step 2: Query attribution for all non-lifecycle events.
        if (event.syscall !== "fork" && event.syscall !== "exec" && event.syscall !== "exit") {
            const attribution = this.tree.attribute(event.pid);
            if (!event.meta)
                event.meta = {};
            event.meta.attribution = attribution;
        }
        // Step 3: For L1 tool_call events, open a correlation window.
        if (event.source === "l1-hook" && event.syscall === "tool_call") {
            this.correlator.open(event);
        }
        // Step 4: For L3 syscall events, check correlation windows.
        if (event.source === "ebpf" || event.source === "uprobe" || event.source === "lsm") {
            const correlationId = this.correlator.correlate(event, this.tree);
            if (correlationId) {
                event.correlationId = correlationId;
            }
            // Step 5: Causal chain detection (only for attributed events).
            if (event.meta?.attribution && event.meta.attribution !== "external") {
                const flags = this.causal.check(event);
                if (flags.length > 0) {
                    if (!event.meta)
                        event.meta = {};
                    event.meta.causalFlags = flags;
                }
            }
        }
        // Step 6: Periodic pruning.
        this.pruneCounter++;
        if (this.pruneCounter >= this.pruneInterval) {
            this.pruneCounter = 0;
            this.prune();
        }
    }
    /**
     * Update the process tree based on the event type.
     */
    updateTree(event) {
        switch (event.syscall) {
            case "fork":
                this.tree.onFork(event);
                break;
            case "exec":
                this.tree.onExec(event);
                break;
            case "exit":
                this.tree.onExit(event);
                break;
            default:
                // Regular syscall — supplement tree with /proc data.
                this.tree.onSyscall(event);
                break;
        }
    }
    /** Prune stale data from all components. */
    prune() {
        this.tree.prune();
        this.correlator.prune();
        this.causal.prune();
    }
    /** Diagnostic: number of processes in the tree. */
    get treeSize() {
        return this.tree.size;
    }
    /** Diagnostic: number of open correlation windows. */
    get openWindows() {
        return this.correlator.openCount;
    }
    /** Diagnostic: number of sessions tracked by causal chain detector. */
    get causalSessionCount() {
        return this.causal.sessionCount;
    }
}
