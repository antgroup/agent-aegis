import type { ProbeEvent } from "../channel/event.js";
import { ProcessTree } from "./process-tree.js";
import { CorrelationWindow } from "./correlation.js";
import { CausalChainDetector } from "./causal-chain.js";

export interface AttributionEngineOptions {
  /** How long a tool-call correlation window stays open (default 30s). */
  correlationWindowMs?: number;
  /** How far back the causal chain detector looks (default 60s). */
  causalWindowMs?: number;
  /** Max process tree nodes before pruning (default 8192). */
  maxTreeNodes?: number;
  /** Process tree stale threshold in ms (default 300000 = 5 min). */
  staleNodeMs?: number;
  /** Process tree prune threshold in ms (default 600000 = 10 min). */
  pruneNodeMs?: number;
  /** Max events per session for causal chain detection (default 500). */
  maxCausalPerSession?: number;
}

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
  private readonly tree: ProcessTree;
  private readonly correlator: CorrelationWindow;
  private readonly causal: CausalChainDetector;
  private pruneCounter = 0;
  private readonly pruneInterval = 100; // Prune every N events

  constructor(opts: AttributionEngineOptions = {}) {
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
  seed(pids: readonly number[]): void {
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
  enrich(event: ProbeEvent): void {
    // Step 1: Update process tree based on event type.
    this.updateTree(event);

    // Step 2: Query attribution for all non-lifecycle events.
    if (event.syscall !== "fork" && event.syscall !== "exec" && event.syscall !== "exit") {
      const attribution = this.tree.attribute(event.pid);
      if (!event.meta) event.meta = {};
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
          if (!event.meta) event.meta = {};
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
  private updateTree(event: ProbeEvent): void {
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
  prune(): void {
    this.tree.prune();
    this.correlator.prune();
    this.causal.prune();
  }

  /** Diagnostic: number of processes in the tree. */
  get treeSize(): number {
    return this.tree.size;
  }

  /** Diagnostic: number of open correlation windows. */
  get openWindows(): number {
    return this.correlator.openCount;
  }

  /** Diagnostic: number of sessions tracked by causal chain detector. */
  get causalSessionCount(): number {
    return this.causal.sessionCount;
  }
}