import type { ProbeEvent } from "../channel/event.js";
import type { ProcessTree } from "./process-tree.js";

/** An active correlation window linking a tool call to its syscalls. */
interface ActiveWindow {
  /** The tool_call event ID — used as correlationId for matching syscalls. */
  id: string;
  /** Tool name that opened the window. */
  toolName: string;
  /** Run/turn ID, if available. */
  runId?: string;
  /** Session key. */
  sessionKey?: string;
  /** PID of the process that initiated the tool call. */
  pid: number;
  /** Epoch ms when the window was opened. */
  openedAt: number;
  /** Epoch ms when the window expires. */
  closeAt: number;
}

export interface CorrelationWindowOptions {
  /** How long a correlation window stays open after a tool_call event (default 30s). */
  windowMs?: number;
}

/**
 * CorrelationWindow maps L1 tool_call events to L3 syscall events.
 *
 * When a tool_call event arrives, we open a window keyed by its event ID.
 * Any syscall event from the same process tree within the window's lifetime
 * gets tagged with that ID as its `correlationId`.
 *
 * The window closes when:
 * - The tool call completes (we see a corresponding event or the window expires)
 * - The window's `closeAt` time is reached (timeout)
 */
export class CorrelationWindow {
  private readonly windows: ActiveWindow[] = [];
  private readonly windowMs: number;

  constructor(opts: CorrelationWindowOptions = {}) {
    this.windowMs = opts.windowMs ?? 30_000;
  }

  /**
   * Open a correlation window when a tool_call event is seen.
   * The event's `id` becomes the `correlationId` for matching syscalls.
   */
  open(event: ProbeEvent): void {
    if (event.syscall !== "tool_call") return;
    const now = Date.now();
    this.windows.push({
      id: event.id,
      toolName: event.toolName ?? (event.args?.toolName as string) ?? "unknown",
      runId: event.runId,
      sessionKey: event.sessionKey,
      pid: event.pid,
      openedAt: now,
      closeAt: now + this.windowMs,
    });
  }

  /**
   * Check if a syscall event falls within any open correlation window.
   * Returns the correlationId (tool_call event ID) if matched, undefined otherwise.
   *
   * A syscall matches a window if:
   * - The window is still open (now < closeAt)
   * - The syscall's sessionKey matches the window's (if both present)
   * - The syscall's PID is the window's PID or a descendant in the process tree
   */
  correlate(event: ProbeEvent, tree: ProcessTree): string | undefined {
    if (event.source === "l1-hook") return undefined; // L1 events don't get correlated
    if (this.windows.length === 0) return undefined;

    const now = Date.now();
    const pid = event.pid;

    for (const w of this.windows) {
      if (now > w.closeAt) continue; // expired

      // Session key must match if both are present.
      if (w.sessionKey && event.sessionKey && w.sessionKey !== event.sessionKey) {
        continue;
      }

      // PID must be the tool-call's PID or a descendant.
      if (pid === w.pid || tree.isDescendantOf(pid, w.pid)) {
        return w.id;
      }

      // Also check if the window's PID is an agent PID and the event's
      // attribution is "agent" or "descendant". This catches cases where
      // the tool call PID is the main agent PID and the syscall comes
      // from a child process that forked after the window opened.
      if (tree.getAgentPids().has(w.pid)) {
        const attr = tree.attribute(pid);
        if (attr === "agent" || attr === "descendant") {
          return w.id;
        }
      }
    }

    return undefined;
  }

  /**
   * Remove expired windows. Call periodically to prevent memory leaks.
   */
  prune(): void {
    const now = Date.now();
    let i = 0;
    while (i < this.windows.length) {
      if (now > this.windows[i].closeAt) {
        this.windows.splice(i, 1);
      } else {
        i++;
      }
    }
  }

  /** Number of currently open windows. */
  get openCount(): number {
    return this.windows.length;
  }
}