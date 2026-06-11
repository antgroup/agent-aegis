import { z } from "zod";
import type { DefenseMode } from "./constants.js";

// ---- Zod validation schema ----

const defenseModeSchema = z.enum(["off", "observe", "enforce"]);

export const aegisConfigSchema = z.object({
  allDefensesEnabled: z.boolean().optional(),
  defaultBlockingMode: defenseModeSchema.optional(),
  selfProtectionEnabled: z.boolean().optional(),
  selfProtectionMode: defenseModeSchema.optional(),
  commandBlockEnabled: z.boolean().optional(),
  commandBlockMode: defenseModeSchema.optional(),
  encodingGuardEnabled: z.boolean().optional(),
  encodingGuardMode: defenseModeSchema.optional(),
  scriptProvenanceGuardEnabled: z.boolean().optional(),
  scriptProvenanceGuardMode: defenseModeSchema.optional(),
  memoryGuardEnabled: z.boolean().optional(),
  memoryGuardMode: defenseModeSchema.optional(),
  userRiskScanEnabled: z.boolean().optional(),
  skillScanEnabled: z.boolean().optional(),
  toolResultScanEnabled: z.boolean().optional(),
  outputRedactionEnabled: z.boolean().optional(),
  promptGuardEnabled: z.boolean().optional(),
  loopGuardEnabled: z.boolean().optional(),
  loopGuardMode: defenseModeSchema.optional(),
  exfiltrationGuardEnabled: z.boolean().optional(),
  exfiltrationGuardMode: defenseModeSchema.optional(),
  toolCallEnforcementEnabled: z.boolean().optional(),
  dispatchGuardEnabled: z.boolean().optional(),
  dispatchGuardMode: defenseModeSchema.optional(),
  protectedPaths: z.array(z.string()).optional(),
  protectedSkills: z.array(z.string()).optional(),
  protectedPlugins: z.array(z.string()).optional(),
  startupSkillScan: z.boolean().optional(),
  webPort: z.number().optional(),
});

export type AegisConfigPartial = z.infer<typeof aegisConfigSchema>;

// ---- Default values ----

export const CONFIG_DEFAULTS = {
  allDefensesEnabled: true,
  defaultBlockingMode: "enforce" as DefenseMode,
  selfProtectionEnabled: true,
  selfProtectionMode: "enforce" as DefenseMode,
  commandBlockEnabled: true,
  commandBlockMode: "enforce" as DefenseMode,
  encodingGuardEnabled: true,
  encodingGuardMode: "enforce" as DefenseMode,
  scriptProvenanceGuardEnabled: true,
  scriptProvenanceGuardMode: "enforce" as DefenseMode,
  memoryGuardEnabled: true,
  memoryGuardMode: "enforce" as DefenseMode,
  userRiskScanEnabled: true,
  skillScanEnabled: true,
  toolResultScanEnabled: true,
  outputRedactionEnabled: true,
  promptGuardEnabled: true,
  loopGuardEnabled: true,
  loopGuardMode: "enforce" as DefenseMode,
  exfiltrationGuardEnabled: true,
  exfiltrationGuardMode: "enforce" as DefenseMode,
  toolCallEnforcementEnabled: true,
  dispatchGuardEnabled: true,
  dispatchGuardMode: "enforce" as DefenseMode,
  protectedPaths: [] as string[],
  protectedSkills: [] as string[],
  protectedPlugins: [] as string[],
  startupSkillScan: true,
};

// ---- Defense group metadata for the UI ----

export type DefenseGroupMeta = {
  id: string;
  label: string;
  help: string;
  enabledKey: string;
  modeKey?: string;
};

export const DEFENSE_GROUPS: DefenseGroupMeta[] = [
  {
    id: "selfProtection",
    label: "Protect Sensitive Paths",
    help: "Block reads, writes, deletes, and searches that target protected paths, important skills, or try to delete files outside the current workspace.",
    enabledKey: "selfProtectionEnabled",
    modeKey: "selfProtectionMode",
  },
  {
    id: "commandBlock",
    label: "Block High-Risk Commands",
    help: "Block clear high-risk shell patterns such as rm -rf / and curl | sh.",
    enabledKey: "commandBlockEnabled",
    modeKey: "commandBlockMode",
  },
  {
    id: "encodingGuard",
    label: "Guard Encoded Payloads",
    help: "Detect bounded base64/base32/hex/url-encoded payloads that hide risky commands or exfiltration logic.",
    enabledKey: "encodingGuardEnabled",
    modeKey: "encodingGuardMode",
  },
  {
    id: "scriptProvenanceGuard",
    label: "Track Script Provenance",
    help: "Track newly written scripts in the current run and block later execution when they carry risky command or exfiltration signals.",
    enabledKey: "scriptProvenanceGuardEnabled",
    modeKey: "scriptProvenanceGuardMode",
  },
  {
    id: "memoryGuard",
    label: "Guard Memory Writes",
    help: "Reject suspicious or oversized writes to memory_store, MEMORY.md, SOUL.md, and memory/.",
    enabledKey: "memoryGuardEnabled",
    modeKey: "memoryGuardMode",
  },
  {
    id: "loopGuard",
    label: "Enable Loop Guard",
    help: "Stop repeated mutating tool calls after the allowed retry budget per run.",
    enabledKey: "loopGuardEnabled",
    modeKey: "loopGuardMode",
  },
  {
    id: "exfiltrationGuard",
    label: "Guard Exfiltration Chains",
    help: "Track prior tool calls per run and block suspicious outbound chains that resemble SSRF or secret exfiltration.",
    enabledKey: "exfiltrationGuardEnabled",
    modeKey: "exfiltrationGuardMode",
  },
  {
    id: "userRiskScan",
    label: "Scan User Intent",
    help: "Detect jailbreak, secret-exfiltration, and plugin-tampering requests in message_received.",
    enabledKey: "userRiskScanEnabled",
  },
  {
    id: "skillScan",
    label: "Scan Skills",
    help: "Enable the lightweight local skill scanner for ~/.openclaw/skills and ~/.openclaw/workspace/skills.",
    enabledKey: "skillScanEnabled",
  },
  {
    id: "toolResultScan",
    label: "Scan Tool Results",
    help: "Scan toolResult content for prompt-injection, secret-request, and exfiltration patterns.",
    enabledKey: "toolResultScanEnabled",
  },
  {
    id: "outputRedaction",
    label: "Redact Sensitive Output",
    help: "Mask API keys, tokens, and similar sensitive values before assistant output is sent or persisted.",
    enabledKey: "outputRedactionEnabled",
  },
  {
    id: "promptGuard",
    label: "Inject Prompt Guards",
    help: "Inject static and one-shot safety reminders during before_prompt_build.",
    enabledKey: "promptGuardEnabled",
  },
  {
    id: "toolCallEnforcement",
    label: "Enforce Tool Call Only",
    help: "Inject prompt rules requiring all destructive operations to go through standard tool calls, preventing bypass of security hooks.",
    enabledKey: "toolCallEnforcementEnabled",
  },
  {
    id: "dispatchGuard",
    label: "Dispatch Guard",
    help: "Intercept dangerous operation requests before they reach the AI agent and before LLM replies, including openclaw CLI commands, protected path destruction, and tool call bypass attempts.",
    enabledKey: "dispatchGuardEnabled",
    modeKey: "dispatchGuardMode",
  },
];
