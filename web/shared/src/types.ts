import type { DefenseMode } from "./constants.js";

// ---- Config ----

export type AegisConfig = {
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
  startupSkillScan: boolean;
  webPort?: number;
};

export type ConfigResponse = {
  config: AegisConfig;
  defaults: AegisConfig;
};

export type ConfigUpdateRequest = Partial<AegisConfig>;

// ---- Status ----

export type DefenseStatusEntry = {
  id: string;
  label: string;
  help: string;
  enabled: boolean;
  mode?: DefenseMode;
};

export type SelfIntegrityStatus = {
  valid: boolean;
  protectedRoots: string[];
  fingerprintCount: number;
  updatedAt: number;
} | null;

export type StatusResponse = {
  defenses: DefenseStatusEntry[];
  integrity: SelfIntegrityStatus;
  trustedSkillCount: number;
  configMtime: string | null;
};

// ---- Events ----

export type SecurityEvent = {
  id: string;
  timestamp: number;
  defense: string;
  result: "blocked" | "observed" | "clear";
  toolName?: string;
  reason?: string;
  details?: Record<string, unknown>;
  commandText?: string;
  toolParams?: Record<string, unknown>;
  userInput?: string;
};

export type EventsResponse = {
  events: SecurityEvent[];
  total: number;
};

// ---- Skill Scan Events ----

export type SkillScanEvent = {
  id: string;
  timestamp: number;
  skillId: string;
  path: string;
  hash: string;
  size: number;
  sourceRoot?: string;
  trusted: boolean;
  findings: string[];
  phase: string;
};

export type SkillScanEventsResponse = {
  events: SkillScanEvent[];
  total: number;
};

// ---- Skills ----

export type TrustedSkillInfo = {
  path: string;
  hash: string;
  size: number;
  sourceRoot?: string;
  scannedAt: number;
};

export type SkillsResponse = {
  trustedSkills: TrustedSkillInfo[];
  total: number;
};

// ---- API wrapper ----

export type ApiOk<T> = { ok: true; data: T };
export type ApiErr = { ok: false; error: string };
export type ApiResponse<T> = ApiOk<T> | ApiErr;

// ---- WebSocket ----

export type WsMessage =
  | { type: "config-changed"; data: AegisConfig }
  | { type: "status-changed"; data: StatusResponse }
  | { type: "event"; data: SecurityEvent }
  | { type: "skills-changed"; data: SkillsResponse };
