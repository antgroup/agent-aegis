import type { ProbeEvent, Verdict } from "../channel/event.js";
import type { Judge } from "./base.js";

/**
 * Native L2/L3 judge — defends against scenarios that L1 cannot see.
 *
 * L1 operates on agent-level tool-call intent. The native judge operates on
 * raw syscall events captured by the eBPF tracepoint/uprobe/LSM probes, so it can catch
 * things like obfuscated `execve` payloads, sub-process file access bypasses,
 * and direct kernel-level exfiltration that never go through the agent's
 * tool registry.
 *
 * M2 ships the structural skeleton plus one demo rule (sensitive-path access
 * via `execve`) so that the multi-judge pipeline can be exercised end-to-end
 * the moment any syscall probe lands. The other slots (kernel-escape,
 * process-tree anomaly) are intentional placeholders.
 */

const JUDGE_ID = "native";

/**
 * Paths whose appearance in any captured syscall argument should be treated
 * as a critical violation. Conservative on purpose — false positives here
 * would block legitimate diagnostic work.
 */
const DEFAULT_SENSITIVE_PATTERNS: readonly RegExp[] = [
  /\/etc\/shadow\b/,
];

/**
 * Filled in M5: directories from which an execve is treated as suspicious.
 * Conservative on purpose — these are well-known scratch / tmpfs locations
 * that legitimate binaries rarely live in.
 */
const DEFAULT_SCRATCH_DIR_PATTERNS: readonly RegExp[] = [
  /^\/tmp\//,
  /^\/var\/tmp\//,
  /^\/dev\/shm\//,
];

export interface NativeJudgeOptions {
  sensitivePathPatterns?: readonly RegExp[];
  /**
   * M5: paths whose execve should be flagged as kernel-escape / suspicious
   * launch location.
   */
  scratchDirPatterns?: readonly RegExp[];
  /**
   * M5: PIDs known to belong to the agent process tree. The first element is
   * the OpenClaw main process; subsequent entries are tracked children. When
   * a syscall's `ppid` is not in this set and not in `expectedAncestors`,
   * `judgeProcessTreeAnomaly` flags the event as observe (never block —
   * false-positive risk is too high without ancestor walks).
   */
  agentPids?: readonly number[];
  /**
   * M5: optional callback that lets the judge query the runtime for the live
   * agent PID set at decision time. Preferred over `agentPids` when the
   * caller cannot pre-compute the list.
   */
  getAgentPids?: () => readonly number[];
}

export function createNativeJudge(opts: NativeJudgeOptions = {}): Judge {
  const patterns = opts.sensitivePathPatterns ?? DEFAULT_SENSITIVE_PATTERNS;
  const scratchPatterns = opts.scratchDirPatterns ?? DEFAULT_SCRATCH_DIR_PATTERNS;
  const resolveAgentPids = (): readonly number[] =>
    opts.getAgentPids?.() ?? opts.agentPids ?? [];
  return {
    id: JUDGE_ID,
    async judge(event: ProbeEvent): Promise<Verdict | null> {
      // Probe-sourced syscalls only. Tool-call events belong to L1.
      if (
        event.source !== "ebpf" &&
        event.source !== "uprobe" &&
        event.source !== "lsm" &&
        event.source !== "test"
      ) {
        return null;
      }

      const sensitive = judgeSensitivePath(event, patterns);
      if (sensitive) return sensitive;

      const escape = judgeKernelEscape(event, scratchPatterns);
      if (escape) return escape;

      const anomaly = judgeProcessTreeAnomaly(event, resolveAgentPids());
      if (anomaly) return anomaly;

      return null;
    },
  };
}

/**
 * Demo rule (filled): block any syscall that touches a sensitive path —
 *   - execve where argv mentions a sensitive path (e.g. `cat /etc/shadow`).
 *   - openat where the target path itself is sensitive (e.g. anything that
 *     opens /etc/shadow, regardless of which binary).
 *
 * Matching `openat` is what `DEFENSE_TRANSITION_PLAN.md §2.2` actually
 * promises: the kernel sees every attempt to open the file, not just
 * children spawned with the path in argv.
 */
function judgeSensitivePath(
  event: ProbeEvent,
  patterns: readonly RegExp[],
): Verdict | null {
  const haystacks: string[] = [];
  if (event.syscall === "execve") {
    const argv = event.args.argv;
    if (Array.isArray(argv)) haystacks.push(argv.map(String).join(" "));
    if (typeof event.args.path === "string") haystacks.push(event.args.path);
  } else if (event.syscall === "openat") {
    if (typeof event.args.path === "string") haystacks.push(event.args.path);
  } else {
    return null;
  }
  if (haystacks.length === 0) return null;

  for (const pattern of patterns) {
    for (const haystack of haystacks) {
      if (pattern.test(haystack)) {
        return {
          action: "block",
          severity: "critical",
          reason: `native: sensitive path access blocked (${pattern.source}); path=${haystack}`,
          judgeId: `${JUDGE_ID}:sensitive-path`,
          confidence: 1,
          sideEffects: [
            {
              kind: "log",
              level: "error",
              message: `pid=${event.pid} ${event.syscall} matched ${pattern.source}: ${haystack}`,
            },
          ],
        };
      }
    }
  }
  return null;
}

/**
 * Filled in M5. Flags execve of binaries that live in well-known scratch
 * directories — these are the "drop a payload, then run it" pattern that
 * `DEFENSE_TRANSITION_PLAN.md` §6 calls out for script-provenance tracing.
 *
 * Conservative scope:
 *   - Only fires when the launch path (`args.path` or argv[0]) is set.
 *   - Default patterns cover /tmp, /var/tmp, /dev/shm. Callers can override
 *     via `NativeJudgeOptions.scratchDirPatterns`.
 *   - Defaults to `block` at `high` severity — the false-positive risk is
 *     low because the patterns are tight.
 */
function judgeKernelEscape(
  event: ProbeEvent,
  scratchPatterns: readonly RegExp[],
): Verdict | null {
  if (event.syscall !== "execve") return null;
  const launchPath = readLaunchPath(event);
  if (!launchPath) return null;
  for (const pattern of scratchPatterns) {
    if (pattern.test(launchPath)) {
      return {
        action: "block",
        severity: "high",
        reason: `native: execve from scratch dir blocked (${pattern.source}); path=${launchPath}`,
        judgeId: `${JUDGE_ID}:kernel-escape`,
        confidence: 0.9,
        sideEffects: [
          {
            kind: "log",
            level: "error",
            message: `pid=${event.pid} launched binary from ${launchPath}`,
          },
        ],
      };
    }
  }
  return null;
}

function readLaunchPath(event: ProbeEvent): string | undefined {
  const fromPath = event.args.path;
  if (typeof fromPath === "string" && fromPath.length > 0) return fromPath;
  const argv = event.args.argv;
  if (Array.isArray(argv) && typeof argv[0] === "string") return argv[0];
  return undefined;
}

/**
 * Filled in M5. Flags syscalls whose parent PID is outside the known agent
 * process tree. Always `observe` (never `block`) — false-positive risk is
 * non-trivial because legitimate agents do spawn detached helpers.
 *
 * Sources of ppid: eBPF / uprobe / LSM probes set `event.meta.ppid` when the
 * kernel tracepoint exposes it, so the rule effectively only fires on
 * eBPF events.
 */
function judgeProcessTreeAnomaly(
  event: ProbeEvent,
  agentPids: readonly number[],
): Verdict | null {
  if (agentPids.length === 0) return null;
  const ppid = readPpid(event);
  if (ppid === undefined) return null;
  if (agentPids.includes(ppid)) return null;
  if (agentPids.includes(event.pid)) return null;
  return {
    action: "observe",
    severity: "low",
    reason: `native: syscall from process outside known agent tree (pid=${event.pid}, ppid=${ppid})`,
    judgeId: `${JUDGE_ID}:process-tree-anomaly`,
    confidence: 0.6,
  };
}

function readPpid(event: ProbeEvent): number | undefined {
  const fromMeta = event.meta?.ppid;
  return typeof fromMeta === "number" ? fromMeta : undefined;
}
