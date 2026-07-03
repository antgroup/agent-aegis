import type { ProbeEvent } from "../channel/event.js";

/**
 * ProcessNode represents a tracked process in the agent's subtree.
 *
 * The tree is built from lifecycle events (fork/exec/exit) and enriched
 * by syscall events carrying /proc data. It enables attribution:
 * "did the agent cause this syscall?"
 */
export interface ProcessNode {
  pid: number;
  ppid: number;
  /** Process start time (kernel clock ticks), from /proc or fork event. */
  startTime?: number;
  /** Short command name (comm). Updated on exec events. */
  comm?: string;
  /** Resolved executable path. Updated on exec events. */
  exe?: string;
  /** Child PIDs that we've seen fork from this process. */
  children: Set<number>;
  /** Session key associated with the process, if known. */
  sessionKey?: string;
  /** Epoch ms when this node was last updated (used for expiry). */
  lastSeen: number;
}

export interface ProcessTreeOptions {
  /** Maximum number of nodes before pruning stale entries. Default 8192. */
  maxNodes?: number;
  /** Time in ms after which a node with no updates is considered stale. Default 300000 (5 min). */
  staleMs?: number;
  /** Time in ms after which a stale node is removed. Default 600000 (10 min). */
  pruneMs?: number;
}

type Attribution = "agent" | "descendant" | "external";

export class ProcessTree {
  private readonly nodes = new Map<number, ProcessNode>();
  private readonly agentPids = new Set<number>();
  private readonly maxNodes: number;
  private readonly staleMs: number;
  private readonly pruneMs: number;

  constructor(opts: ProcessTreeOptions = {}) {
    this.maxNodes = opts.maxNodes ?? 8192;
    this.staleMs = opts.staleMs ?? 5 * 60 * 1000;
    this.pruneMs = opts.pruneMs ?? 10 * 60 * 1000;
  }

  /**
   * Seed the tree with the known agent PID(s).
   * Called at startup with runtime.getCurrentContext().pids.
   */
  seed(pids: readonly number[]): void {
    for (const pid of pids) {
      this.agentPids.add(pid);
      // If we don't already have a node for this PID, create a minimal one.
      if (!this.nodes.has(pid)) {
        this.nodes.set(pid, {
          pid,
          ppid: 0,
          children: new Set(),
          lastSeen: Date.now(),
        });
      }
    }
  }

  /**
   * Process a lifecycle "fork" event.
   * Creates a child node and links it to the parent.
   */
  onFork(event: ProbeEvent): void {
    const parentPid = event.pid;
    const childPid = (event.meta?.forkChildPid as number) ?? event.pid;
    const now = Date.now();

    // Ensure parent node exists.
    let parent = this.nodes.get(parentPid);
    if (!parent) {
      parent = {
        pid: parentPid,
        ppid: event.proc?.ppid ?? 0,
        comm: event.proc?.comm,
        children: new Set(),
        sessionKey: event.sessionKey,
        lastSeen: now,
      };
      this.nodes.set(parentPid, parent);
    } else {
      parent.lastSeen = now;
      parent.sessionKey = event.sessionKey ?? parent.sessionKey;
    }

    // Create or update child node.
    let child = this.nodes.get(childPid);
    if (!child) {
      child = {
        pid: childPid,
        ppid: parentPid,
        comm: event.proc?.comm,
        children: new Set(),
        sessionKey: event.sessionKey,
        lastSeen: now,
      };
      this.nodes.set(childPid, child);
    } else {
      child.ppid = parentPid;
      child.lastSeen = now;
      child.sessionKey = event.sessionKey ?? child.sessionKey;
    }

    // Link parent → child.
    parent.children.add(childPid);

    this.maybePrune();
  }

  /**
   * Process a lifecycle "exec" event.
   * Updates comm/exe for the process (exec replaces the image).
   */
  onExec(event: ProbeEvent): void {
    const pid = event.pid;
    const now = Date.now();
    let node = this.nodes.get(pid);
    if (!node) {
      node = {
        pid,
        ppid: event.proc?.ppid ?? 0,
        comm: event.proc?.comm,
        exe: event.args?.path as string | undefined ?? event.proc?.exe,
        children: new Set(),
        sessionKey: event.sessionKey,
        lastSeen: now,
      };
      this.nodes.set(pid, node);
    } else {
      node.comm = event.proc?.comm ?? node.comm;
      node.exe = (event.args?.path as string | undefined) ?? event.proc?.exe ?? node.exe;
      node.lastSeen = now;
      node.sessionKey = event.sessionKey ?? node.sessionKey;
    }

    this.maybePrune();
  }

  /**
   * Process a lifecycle "exit" event.
   * Removes the node and unlinks it from its parent.
   */
  onExit(event: ProbeEvent): void {
    const pid = event.pid;
    const node = this.nodes.get(pid);
    if (!node) return;

    // Unlink from parent.
    const parent = this.nodes.get(node.ppid);
    if (parent) {
      parent.children.delete(pid);
    }

    // Remove children that have this pid as parent (orphan re-parenting
    // is complex; we simply detach them — they'll be attributed as
    // "external" unless they're re-discovered).
    this.nodes.delete(pid);

    this.maybePrune();
  }

  /**
   * Process a syscall event (ebpf/uprobe/lsm).
   * Supplements the tree with /proc data from event.proc.
   */
  onSyscall(event: ProbeEvent): void {
    const pid = event.pid;
    const now = Date.now();
    let node = this.nodes.get(pid);
    if (!node) {
      // Create a minimal node from syscall data. We don't know if this
      // is an agent descendant yet — that's determined by attribute().
      node = {
        pid,
        ppid: event.proc?.ppid ?? 0,
        comm: event.proc?.comm,
        exe: event.proc?.exe,
        startTime: event.proc?.startTime,
        children: new Set(),
        sessionKey: event.sessionKey,
        lastSeen: now,
      };
      this.nodes.set(pid, node);
    } else {
      // Update with fresh data.
      node.lastSeen = now;
      if (event.proc?.comm) node.comm = event.proc.comm;
      if (event.proc?.exe) node.exe = event.proc.exe;
      if (event.proc?.startTime) node.startTime = event.proc.startTime;
      if (event.sessionKey) node.sessionKey = event.sessionKey;
    }
    // Use ancestors from /proc to fill in missing tree links.
    // This applies to both new and existing nodes.
    if (event.proc?.ancestors && event.proc.ancestors.length > 0) {
      this.linkAncestors(pid, event.proc.ancestors, now);
    }

    this.maybePrune();
  }

  /**
   * Attribute a PID: is it the agent, a descendant, or external?
   */
  attribute(pid: number): Attribution {
    if (this.agentPids.has(pid)) return "agent";
    if (this.isDescendantOfAgent(pid)) return "descendant";
    return "external";
  }

  /**
   * Check if `pid` is a descendant of `ancestorPid` by walking up the
   * parent chain. Also returns true if pid === ancestorPid.
   */
  isDescendantOf(pid: number, ancestorPid: number): boolean {
    if (pid === ancestorPid) return true;
    const visited = new Set<number>();
    let current = pid;
    while (current > 0 && !visited.has(current)) {
      visited.add(current);
      const node = this.nodes.get(current);
      if (!node) break;
      if (node.ppid === ancestorPid) return true;
      current = node.ppid;
    }
    return false;
  }

  /**
   * Check if a PID is a descendant of any agent PID, using BFS.
   * Also considers PIDs that are not in the tree but have an
   * ancestor chain leading to an agent PID.
   */
  private isDescendantOfAgent(pid: number): boolean {
    // Quick check: is it recorded as a child of an agent pid?
    const visited = new Set<number>();
    const queue = [pid];
    while (queue.length > 0) {
      const current = queue.shift()!;
      if (visited.has(current)) continue;
      visited.add(current);

      if (this.agentPids.has(current)) return true;

      const node = this.nodes.get(current);
      if (!node) continue;

      // Walk up to parent.
      if (node.ppid > 0) {
        queue.push(node.ppid);
      }
    }
    return false;
  }

  /**
   * Link ancestors into the tree from /proc data.
   * This fills in gaps where we missed fork events but /proc
   * still has the ancestor chain.
   */
  private linkAncestors(pid: number, ancestors: number[], now: number): void {
    // ancestors[0] is the direct parent, ancestors[1] is grandparent, etc.
    let childPid = pid;
    for (const ancestorPid of ancestors) {
      if (ancestorPid <= 0) break;
      let ancestor = this.nodes.get(ancestorPid);
      if (!ancestor) {
        ancestor = {
          pid: ancestorPid,
          ppid: 0, // We don't know the grandparent's parent from this data.
          children: new Set(),
          lastSeen: now,
        };
        this.nodes.set(ancestorPid, ancestor);
      }
      ancestor.children.add(childPid);
      // Update the child's ppid if it was 0.
      const child = this.nodes.get(childPid);
      if (child && child.ppid === 0) {
        child.ppid = ancestorPid;
      }
      childPid = ancestorPid;
    }
  }

  /**
   * Remove stale nodes that haven't been seen for pruneMs.
   */
  prune(): void {
    const now = Date.now();
    const toRemove: number[] = [];
    for (const [pid, node] of this.nodes) {
      // Never prune agent PIDs.
      if (this.agentPids.has(pid)) continue;
      if (now - node.lastSeen > this.pruneMs) {
        toRemove.push(pid);
      }
    }
    for (const pid of toRemove) {
      const node = this.nodes.get(pid);
      if (node) {
        // Unlink from parent.
        const parent = this.nodes.get(node.ppid);
        if (parent) parent.children.delete(pid);
        this.nodes.delete(pid);
      }
    }
  }

  /**
   * Prune if we've exceeded maxNodes.
   */
  private maybePrune(): void {
    if (this.nodes.size > this.maxNodes) {
      this.prune();
    }
  }

  /** Current number of tracked processes. */
  get size(): number {
    return this.nodes.size;
  }

  /** Get a node by PID (for testing/diagnostics). */
  getNode(pid: number): ProcessNode | undefined {
    return this.nodes.get(pid);
  }

  /** Get all agent PIDs. */
  getAgentPids(): ReadonlySet<number> {
    return this.agentPids;
  }

  /** Check if the tree is empty. */
  get isEmpty(): boolean {
    return this.nodes.size === 0;
  }
}