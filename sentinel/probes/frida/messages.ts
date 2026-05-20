/**
 * Wire protocol between the Frida-injected agent script and the Node loader.
 *
 * Pinning this contract early prevents schema drift as M4.5 adds enforce-mode
 * messages and Windows agents land. Add new variants here, do not invent
 * ad-hoc shapes in agent.js.
 */
export type AgentMessage =
  | SyscallMessage
  | LogMessage
  | ErrorMessage
  | ReadyMessage
  | UnsupportedMessage
  | DecisionRequestMessage
  | DecisionResponseMessage;

export interface SyscallMessage {
  kind: "syscall";
  syscall: string;
  pid: number;
  ts: number;
  /** Present for execve. */
  argv?: string[];
  /** Present for openat/open/file-related syscalls. */
  path?: string;
  /** Present for connect/network-related syscalls. */
  addr?: string;
  /** Extra fields the probe may add without breaking schema; sentinel passes through. */
  extra?: Record<string, unknown>;
}

export interface LogMessage {
  kind: "log";
  level: "debug" | "info" | "warn" | "error";
  message: string;
}

export interface ErrorMessage {
  kind: "error";
  where: string;
  message: string;
}

export interface ReadyMessage {
  kind: "ready";
  hookedTargets: string[];
}

export interface UnsupportedMessage {
  kind: "unsupported";
  platform: string;
}

/**
 * Added in M4.5. Sent by agent on enforce-mode syscall entry. The loader
 * must answer with a {@link DecisionResponseMessage} that has the matching id.
 */
export interface DecisionRequestMessage {
  kind: "decision_request";
  id: string;
  syscall: string;
  pid: number;
  argv?: string[];
  path?: string;
}

/**
 * Added in M4.5. Loader's response to a decision_request, posted back to the
 * agent via `script.post()`. "deny" makes the agent return -EACCES; "allow"
 * lets the original syscall through.
 */
export interface DecisionResponseMessage {
  kind: "decision_response";
  id: string;
  decision: "allow" | "deny";
  reason?: string;
}

/**
 * Parse an arbitrary payload received from the agent script into an
 * AgentMessage. Returns null when the payload is malformed; the caller is
 * expected to log and drop. Defensive on purpose — the Frida script runs in
 * an arbitrary process and could be tampered with.
 */
export function parseAgentMessage(raw: unknown): AgentMessage | null {
  if (!raw || typeof raw !== "object") return null;
  const r = raw as Record<string, unknown>;
  const kind = r.kind;
  switch (kind) {
    case "syscall":
      return parseSyscall(r);
    case "log":
      return parseLog(r);
    case "error":
      return parseError(r);
    case "ready":
      return parseReady(r);
    case "unsupported":
      return parseUnsupported(r);
    case "decision_request":
      return parseDecisionRequest(r);
    case "decision_response":
      return parseDecisionResponse(r);
    default:
      return null;
  }
}

function parseSyscall(r: Record<string, unknown>): SyscallMessage | null {
  if (typeof r.syscall !== "string") return null;
  const pid = typeof r.pid === "number" ? r.pid : 0;
  const ts = typeof r.ts === "number" ? r.ts : Date.now();
  const out: SyscallMessage = { kind: "syscall", syscall: r.syscall, pid, ts };
  if (Array.isArray(r.argv) && r.argv.every((s) => typeof s === "string")) {
    out.argv = r.argv as string[];
  }
  if (typeof r.path === "string") out.path = r.path;
  if (typeof r.addr === "string") out.addr = r.addr;
  if (r.extra && typeof r.extra === "object" && !Array.isArray(r.extra)) {
    out.extra = r.extra as Record<string, unknown>;
  }
  return out;
}

function parseLog(r: Record<string, unknown>): LogMessage | null {
  const level = r.level;
  if (level !== "debug" && level !== "info" && level !== "warn" && level !== "error") return null;
  if (typeof r.message !== "string") return null;
  return { kind: "log", level, message: r.message };
}

function parseError(r: Record<string, unknown>): ErrorMessage | null {
  if (typeof r.where !== "string" || typeof r.message !== "string") return null;
  return { kind: "error", where: r.where, message: r.message };
}

function parseReady(r: Record<string, unknown>): ReadyMessage | null {
  if (!Array.isArray(r.hookedTargets)) return null;
  if (!r.hookedTargets.every((s) => typeof s === "string")) return null;
  return { kind: "ready", hookedTargets: r.hookedTargets as string[] };
}

function parseUnsupported(r: Record<string, unknown>): UnsupportedMessage | null {
  if (typeof r.platform !== "string") return null;
  return { kind: "unsupported", platform: r.platform };
}

function parseDecisionRequest(r: Record<string, unknown>): DecisionRequestMessage | null {
  if (typeof r.id !== "string" || typeof r.syscall !== "string") return null;
  const pid = typeof r.pid === "number" ? r.pid : 0;
  const out: DecisionRequestMessage = { kind: "decision_request", id: r.id, syscall: r.syscall, pid };
  if (Array.isArray(r.argv) && r.argv.every((s) => typeof s === "string")) {
    out.argv = r.argv as string[];
  }
  if (typeof r.path === "string") out.path = r.path;
  return out;
}

function parseDecisionResponse(r: Record<string, unknown>): DecisionResponseMessage | null {
  if (typeof r.id !== "string") return null;
  if (r.decision !== "allow" && r.decision !== "deny") return null;
  const out: DecisionResponseMessage = { kind: "decision_response", id: r.id, decision: r.decision };
  if (typeof r.reason === "string") out.reason = r.reason;
  return out;
}
