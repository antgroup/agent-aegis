import path from "node:path";
import type { OpenClawPluginApi, OpenClawPluginConfigSchema } from "../runtime-api.js";

export const CLAW_AEGIS_PLUGIN_ID = "agent-aegis";
export const DEFENSE_MODES = ["off", "observe", "enforce"] as const;

export const TURN_STATE_TTL_MS = 5 * 60_000;
export const LOOP_GUARD_TTL_MS = 5 * 60_000;
export const LOOP_GUARD_ALLOW_COUNT = 3;

export const STARTUP_SCAN_BUDGET_MS = 200;
export const INLINE_EXEC_TEXT_MAX_CHARS = 8 * 1024;
export const MEMORY_WRITE_MAX_CHARS = 8 * 1024;
export const MEMORY_WRITE_MAX_LINES = 200;
export const TOOL_RESULT_CHAR_BUDGET = 64 * 1024;
export const TOOL_RESULT_MAX_DEPTH = 4;
export const TOOL_RESULT_MAX_ARRAY_ITEMS = 200;

export const SKILL_SCAN_QUEUE_MAX = 16;
export const SKILL_SCAN_TIMEOUT_MS = 3000;
export const SKILL_SCAN_COOLDOWN_MS = 5 * 60_000;
export const SKILL_SCAN_FAILURE_WINDOW_MS = 60_000;
export const SKILL_SCAN_FAILURE_THRESHOLD = 3;
export const SKILL_SCAN_FILE_MAX_BYTES = 100 * 1024;
export const SKILL_SCAN_TARGET_FILENAME = "SKILL.md";

export const TRUSTED_SKILLS_FILENAME = "trusted-skills.json";
export const SELF_INTEGRITY_FILENAME = "self-integrity.json";
export const DEFENSE_EVENTS_FILENAME = "defense-events.jsonl";
export const SKILL_SCAN_EVENTS_FILENAME = "skill-scan-events.jsonl";

export const BLOCK_REASON_PROTECTED_PATH =
  "安全限制：禁止访问、查询、修改、删除、关闭或绕过受保护的敏感路径、配置、重要 skill 或 claw-aegis 插件目录。";
export const BLOCK_REASON_WORKSPACE_DELETE =
  "安全限制：禁止删除 workspace 之外的路径。";
export const BLOCK_REASON_OPENCLAW_COMMAND =
  "安全限制：禁止执行 openclaw CLI 或控制命令。";
export const BLOCK_REASON_HIGH_RISK_OPERATION = "安全限制：已阻止本次高风险操作请求。";
export const BLOCK_REASON_MEMORY_WRITE = "安全限制：已拒绝本次高风险记忆写入。";
export const BLOCK_REASON_LOOP = "安全限制：检测到重复高风险工具调用，已停止本次操作。";
export const BLOCK_REASON_EXFILTRATION_CHAIN =
  "安全限制：检测到疑似 SSRF 或数据外泄工具调用链，已阻止本次出站请求。";
export const BLOCK_REASON_DISPATCH_GUARD =
  "安全限制：检测到针对受保护资源的危险操作请求，已拦截。所有破坏性操作必须通过标准 tool call 执行。";

export type DefenseMode = (typeof DEFENSE_MODES)[number];

export type ClawAegisPluginConfig = {
  allDefensesEnabled: boolean;
  defaultBlockingMode: DefenseMode;
  selfProtectionEnabled: boolean;
  selfProtectionMode: DefenseMode;
  commandBlockEnabled: boolean;
  commandBlockMode: DefenseMode;
  encodingGuardEnabled: boolean;
  encodingGuardMode: DefenseMode;
  scriptProvenanceGuardEnabled: boolean;
  scriptProvenanceGuardMode: DefenseMode;
  memoryGuardEnabled: boolean;
  memoryGuardMode: DefenseMode;
  userRiskScanEnabled: boolean;
  skillScanEnabled: boolean;
  toolResultScanEnabled: boolean;
  outputRedactionEnabled: boolean;
  promptGuardEnabled: boolean;
  loopGuardEnabled: boolean;
  loopGuardMode: DefenseMode;
  exfiltrationGuardEnabled: boolean;
  exfiltrationGuardMode: DefenseMode;
  toolCallEnforcementEnabled: boolean;
  dispatchGuardEnabled: boolean;
  dispatchGuardMode: DefenseMode;
  protectedPaths: string[];
  protectedSkills: string[];
  protectedPlugins: string[];
  skillRoots: string[];
  extraProtectedRoots: string[];
  startupSkillScan: boolean;
};

const defaultEnabledBooleanSchema = {
  type: "boolean",
  default: true,
} as const;

const defaultDefenseModeSchema = {
  type: "string",
  enum: [...DEFENSE_MODES],
  default: "enforce",
} as const;

export const clawAegisPluginConfigSchema = {
  type: "object",
  additionalProperties: false,
  properties: {
    allDefensesEnabled: defaultEnabledBooleanSchema,
    defaultBlockingMode: defaultDefenseModeSchema,
    selfProtectionEnabled: defaultEnabledBooleanSchema,
    selfProtectionMode: defaultDefenseModeSchema,
    commandBlockEnabled: defaultEnabledBooleanSchema,
    commandBlockMode: defaultDefenseModeSchema,
    encodingGuardEnabled: defaultEnabledBooleanSchema,
    encodingGuardMode: defaultDefenseModeSchema,
    scriptProvenanceGuardEnabled: defaultEnabledBooleanSchema,
    scriptProvenanceGuardMode: defaultDefenseModeSchema,
    memoryGuardEnabled: defaultEnabledBooleanSchema,
    memoryGuardMode: defaultDefenseModeSchema,
    userRiskScanEnabled: defaultEnabledBooleanSchema,
    skillScanEnabled: defaultEnabledBooleanSchema,
    toolResultScanEnabled: defaultEnabledBooleanSchema,
    outputRedactionEnabled: defaultEnabledBooleanSchema,
    promptGuardEnabled: defaultEnabledBooleanSchema,
    loopGuardEnabled: defaultEnabledBooleanSchema,
    loopGuardMode: defaultDefenseModeSchema,
    exfiltrationGuardEnabled: defaultEnabledBooleanSchema,
    exfiltrationGuardMode: defaultDefenseModeSchema,
    toolCallEnforcementEnabled: defaultEnabledBooleanSchema,
    dispatchGuardEnabled: defaultEnabledBooleanSchema,
    dispatchGuardMode: defaultDefenseModeSchema,
    protectedPaths: {
      type: "array",
      items: { type: "string" },
    },
    protectedSkills: {
      type: "array",
      items: { type: "string" },
    },
    protectedPlugins: {
      type: "array",
      items: { type: "string" },
    },
    skillRoots: {
      type: "array",
      items: { type: "string" },
    },
    extraProtectedRoots: {
      type: "array",
      items: { type: "string" },
    },
    startupSkillScan: {
      type: "boolean",
      default: true,
    },
  },
} satisfies OpenClawPluginConfigSchema["jsonSchema"];

export const clawAegisPluginUiHints = {
  allDefensesEnabled: {
    label: "Enable All Defenses",
    help: "Master switch for every claw-aegis defense below.",
  },
  defaultBlockingMode: {
    label: "Default Blocking Mode",
    help: 'Default mode for blocking defenses. "enforce" blocks, "observe" only logs, and "off" disables the guard.',
  },
  selfProtectionEnabled: {
    label: "Protect Sensitive Paths",
    help: "Block reads, writes, deletes, and searches that target protected paths, important skills, or try to delete files outside the current workspace.",
  },
  selfProtectionMode: {
    label: "Sensitive Path Mode",
    help: 'Detailed mode for protected-path defenses. "observe" records violations without blocking.',
  },
  commandBlockEnabled: {
    label: "Block High-Risk Commands",
    help: "Block clear high-risk shell patterns such as rm -rf / and curl | sh.",
  },
  commandBlockMode: {
    label: "Command Block Mode",
    help: 'Detailed mode for high-risk command blocking. "observe" only reports detections.',
  },
  encodingGuardEnabled: {
    label: "Guard Encoded Payloads",
    help: "Detect bounded base64/base32/hex/url-encoded payloads that hide risky commands or exfiltration logic.",
  },
  encodingGuardMode: {
    label: "Encoding Guard Mode",
    help: 'Detailed mode for encoded/obfuscated command guards. "observe" keeps the call allowed.',
  },
  scriptProvenanceGuardEnabled: {
    label: "Track Script Provenance",
    help: "Track newly written scripts in the current run and block later execution when they carry risky command or exfiltration signals.",
  },
  scriptProvenanceGuardMode: {
    label: "Script Provenance Mode",
    help: 'Detailed mode for risky script provenance enforcement. "observe" logs the execution attempt only.',
  },
  memoryGuardEnabled: {
    label: "Guard Memory Writes",
    help: "Reject suspicious or oversized writes to memory_store, MEMORY.md, SOUL.md, and memory/.",
  },
  memoryGuardMode: {
    label: "Memory Guard Mode",
    help: 'Detailed mode for risky memory writes. "observe" will keep the write allowed.',
  },
  userRiskScanEnabled: {
    label: "Scan User Intent",
    help: "Detect jailbreak, secret-exfiltration, and plugin-tampering requests in message_received.",
  },
  skillScanEnabled: {
    label: "Scan Skills",
    help: "Enable the lightweight local skill scanner for ~/.openclaw/skills and ~/.openclaw/workspace/skills.",
  },
  toolResultScanEnabled: {
    label: "Scan Tool Results",
    help: "Scan toolResult content for prompt-injection, secret-request, and exfiltration patterns.",
  },
  outputRedactionEnabled: {
    label: "Redact Sensitive Output",
    help: "Mask API keys, tokens, and similar sensitive values before assistant output is sent or persisted.",
  },
  promptGuardEnabled: {
    label: "Inject Prompt Guards",
    help: "Inject static and one-shot safety reminders during before_prompt_build.",
  },
  loopGuardEnabled: {
    label: "Enable Loop Guard",
    help: "Stop repeated mutating tool calls after the allowed retry budget per run.",
  },
  loopGuardMode: {
    label: "Loop Guard Mode",
    help: 'Detailed mode for repeated mutating calls. "observe" warns instead of stopping the run.',
  },
  exfiltrationGuardEnabled: {
    label: "Guard Exfiltration Chains",
    help: "Track prior tool calls per run and block suspicious outbound chains that resemble SSRF or secret exfiltration.",
  },
  exfiltrationGuardMode: {
    label: "Exfiltration Guard Mode",
    help: 'Detailed mode for outbound chain detection. "observe" records the chain without blocking.',
  },
  toolCallEnforcementEnabled: {
    label: "Enforce Tool Call Only",
    help: "Inject prompt rules requiring all destructive operations (file ops, CLI commands, network, process spawning) to go through standard tool calls only.",
  },
  dispatchGuardEnabled: {
    label: "Guard Message Dispatch",
    help: "Intercept user messages and LLM replies before agent processing to block dangerous operations targeting protected resources.",
  },
  dispatchGuardMode: {
    label: "Dispatch Guard Mode",
    help: 'Detailed mode for dispatch guard. "enforce" blocks dangerous messages, "observe" only logs.',
  },
  protectedPaths: {
    label: "Protected Paths",
    help: "Additional absolute or resolved paths that should be treated as protected targets.",
    advanced: true,
    placeholder: "/path/to/protected",
  },
  protectedSkills: {
    label: "Protected Skills",
    help: "Additional skill IDs to protect under ~/.openclaw/skills and ~/.openclaw/workspace/skills.",
    advanced: true,
    placeholder: "release-guard",
  },
  protectedPlugins: {
    label: "Protected Plugins",
    help: "Additional plugin IDs to protect under extensions/, plugins/ state, and openclaw.json plugin entries.",
    advanced: true,
    placeholder: "audit-guard",
  },
  startupSkillScan: {
    label: "Scan Skills at Startup",
    help: "Run a bounded startup scan for ~/.openclaw/skills and ~/.openclaw/workspace/skills.",
    advanced: true,
  },
  skillRoots: {
    label: "Additional Skill Roots (Ignored)",
    help: "Deprecated. claw-aegis v1 now scans only ~/.openclaw/skills and ~/.openclaw/workspace/skills.",
    advanced: true,
    placeholder: "/path/to/skills",
  },
  extraProtectedRoots: {
    label: "Additional Protected Roots",
    help: "Legacy compatibility alias of protectedPaths. Extra directories that claw-aegis should treat as protected paths.",
    advanced: true,
    placeholder: "/path/to/protected",
  },
} satisfies NonNullable<OpenClawPluginConfigSchema["uiHints"]>;

export const clawAegisPluginConfigDefinition = {
  jsonSchema: clawAegisPluginConfigSchema,
  uiHints: clawAegisPluginUiHints,
} satisfies OpenClawPluginConfigSchema;

function normalizeStringList(value: unknown, resolvePath: (input: string) => string): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const seen = new Set<string>();
  const results: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") {
      continue;
    }
    const trimmed = entry.trim();
    if (!trimmed) {
      continue;
    }
    const resolved = path.resolve(resolvePath(trimmed));
    if (seen.has(resolved)) {
      continue;
    }
    seen.add(resolved);
    results.push(resolved);
  }
  return results;
}

function normalizeIdentifierList(value: unknown): string[] {
  if (!Array.isArray(value)) {
    return [];
  }
  const seen = new Set<string>();
  const results: string[] = [];
  for (const entry of value) {
    if (typeof entry !== "string") {
      continue;
    }
    const normalized = entry.trim().normalize("NFKC").toLowerCase();
    if (!normalized || seen.has(normalized)) {
      continue;
    }
    seen.add(normalized);
    results.push(normalized);
  }
  return results;
}

function readEnabledFlag(
  raw: Record<string, unknown>,
  key: keyof Pick<
    ClawAegisPluginConfig,
    | "selfProtectionEnabled"
    | "commandBlockEnabled"
    | "encodingGuardEnabled"
    | "scriptProvenanceGuardEnabled"
    | "memoryGuardEnabled"
    | "userRiskScanEnabled"
    | "skillScanEnabled"
    | "toolResultScanEnabled"
    | "outputRedactionEnabled"
    | "promptGuardEnabled"
    | "loopGuardEnabled"
    | "exfiltrationGuardEnabled"
    | "toolCallEnforcementEnabled"
    | "dispatchGuardEnabled"
  >,
  allDefensesEnabled: boolean,
): boolean {
  return allDefensesEnabled && raw[key] !== false;
}

function isDefenseMode(value: unknown): value is DefenseMode {
  return typeof value === "string" && (DEFENSE_MODES as readonly string[]).includes(value);
}

function readDefenseMode(
  raw: Record<string, unknown>,
  params: {
    enabledKey: keyof Pick<
      ClawAegisPluginConfig,
      | "selfProtectionEnabled"
      | "commandBlockEnabled"
      | "encodingGuardEnabled"
      | "scriptProvenanceGuardEnabled"
      | "memoryGuardEnabled"
      | "loopGuardEnabled"
      | "exfiltrationGuardEnabled"
      | "dispatchGuardEnabled"
    >;
    modeKey: keyof Pick<
      ClawAegisPluginConfig,
      | "selfProtectionMode"
      | "commandBlockMode"
      | "encodingGuardMode"
      | "scriptProvenanceGuardMode"
      | "memoryGuardMode"
      | "loopGuardMode"
      | "exfiltrationGuardMode"
      | "dispatchGuardMode"
    >;
    defaultMode: DefenseMode;
    allDefensesEnabled: boolean;
  },
): DefenseMode {
  if (!params.allDefensesEnabled || raw[params.enabledKey] === false) {
    return "off";
  }
  const explicitMode = raw[params.modeKey];
  return isDefenseMode(explicitMode) ? explicitMode : params.defaultMode;
}

export function resolveClawAegisPluginConfig(api: OpenClawPluginApi): ClawAegisPluginConfig {
  const raw = (api.pluginConfig ?? {}) as Record<string, unknown>;
  const allDefensesEnabled = raw.allDefensesEnabled !== false;
  const defaultBlockingMode = isDefenseMode(raw.defaultBlockingMode)
    ? raw.defaultBlockingMode
    : "enforce";
  const selfProtectionMode = readDefenseMode(raw, {
    enabledKey: "selfProtectionEnabled",
    modeKey: "selfProtectionMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const commandBlockMode = readDefenseMode(raw, {
    enabledKey: "commandBlockEnabled",
    modeKey: "commandBlockMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const encodingGuardMode = readDefenseMode(raw, {
    enabledKey: "encodingGuardEnabled",
    modeKey: "encodingGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const scriptProvenanceGuardMode = readDefenseMode(raw, {
    enabledKey: "scriptProvenanceGuardEnabled",
    modeKey: "scriptProvenanceGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const memoryGuardMode = readDefenseMode(raw, {
    enabledKey: "memoryGuardEnabled",
    modeKey: "memoryGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const loopGuardMode = readDefenseMode(raw, {
    enabledKey: "loopGuardEnabled",
    modeKey: "loopGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const exfiltrationGuardMode = readDefenseMode(raw, {
    enabledKey: "exfiltrationGuardEnabled",
    modeKey: "exfiltrationGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  const dispatchGuardMode = readDefenseMode(raw, {
    enabledKey: "dispatchGuardEnabled",
    modeKey: "dispatchGuardMode",
    defaultMode: defaultBlockingMode,
    allDefensesEnabled,
  });
  return {
    allDefensesEnabled,
    defaultBlockingMode,
    selfProtectionEnabled: selfProtectionMode !== "off",
    selfProtectionMode,
    commandBlockEnabled: commandBlockMode !== "off",
    commandBlockMode,
    encodingGuardEnabled: encodingGuardMode !== "off",
    encodingGuardMode,
    scriptProvenanceGuardEnabled: scriptProvenanceGuardMode !== "off",
    scriptProvenanceGuardMode,
    memoryGuardEnabled: memoryGuardMode !== "off",
    memoryGuardMode,
    userRiskScanEnabled: readEnabledFlag(raw, "userRiskScanEnabled", allDefensesEnabled),
    skillScanEnabled: readEnabledFlag(raw, "skillScanEnabled", allDefensesEnabled),
    toolResultScanEnabled: readEnabledFlag(raw, "toolResultScanEnabled", allDefensesEnabled),
    outputRedactionEnabled: readEnabledFlag(raw, "outputRedactionEnabled", allDefensesEnabled),
    promptGuardEnabled: readEnabledFlag(raw, "promptGuardEnabled", allDefensesEnabled),
    loopGuardEnabled: loopGuardMode !== "off",
    loopGuardMode,
    exfiltrationGuardEnabled: exfiltrationGuardMode !== "off",
    exfiltrationGuardMode,
    toolCallEnforcementEnabled: readEnabledFlag(raw, "toolCallEnforcementEnabled", allDefensesEnabled),
    dispatchGuardEnabled: dispatchGuardMode !== "off",
    dispatchGuardMode,
    protectedPaths: normalizeStringList(raw.protectedPaths, api.resolvePath),
    protectedSkills: normalizeIdentifierList(raw.protectedSkills),
    protectedPlugins: normalizeIdentifierList(raw.protectedPlugins),
    skillRoots: normalizeStringList(raw.skillRoots, api.resolvePath),
    extraProtectedRoots: normalizeStringList(raw.extraProtectedRoots, api.resolvePath),
    startupSkillScan: raw.startupSkillScan !== false,
  };
}

export function resolveClawAegisStateDir(api: OpenClawPluginApi): string {
  return path.join(api.runtime.state.resolveStateDir(), "plugins", CLAW_AEGIS_PLUGIN_ID);
}

export function resolveSkillScanRoots(api: OpenClawPluginApi): string[] {
  const stateRoot = path.resolve(api.runtime.state.resolveStateDir());
  return [path.join(stateRoot, "skills"), path.join(stateRoot, "workspace", "skills")];
}
