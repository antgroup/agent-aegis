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

// ---- Sentinel (L2/L3 kernel defense) config ----

export type SentinelBehaviorRuleConfig = {
  enabled?: boolean;
  action?: "allow" | "observe" | "block";
  severity?: "info" | "low" | "medium" | "high" | "critical";
  confidence?: number;
  windowMs?: number;
  thresholds?: Record<string, number>;
  patterns?: Record<string, string[]>;
  options?: Record<string, unknown>;
  [key: string]: unknown;
};

export type SentinelResponsePolicyConfig = {
  enabled: boolean;
  mode: "off" | "observe" | "enforce";
  minAlertConfidence: number;
  minBlockConfidence: number;
  minKillConfidence: number;
  blockSeverity: "info" | "low" | "medium" | "high" | "critical";
  killSeverity: "info" | "low" | "medium" | "high" | "critical";
  allowKill: boolean;
  allowThrottle: boolean;
  allowIsolate: boolean;
  safeAttributions: string[];
};

export type SentinelConfig = {
  stateDir: string;
  nativeJudge: {
    mode: "observe" | "enforce";
    sensitivePaths: string[];
    scratchDirs: string[];
  };
  probes: {
    ebpf: { enabled: boolean };
    uprobe: { enabled: boolean };
    lsm: { enabled: boolean; minSeverity: "high" | "critical" };
  };
  sentinel: {
    behaviorJudge: {
      enabled: boolean;
      mode: "off" | "observe" | "enforce";
      minEvents: number;
      recentCount: number;
      rules: Record<string, SentinelBehaviorRuleConfig | boolean>;
    };
    responsePolicy: SentinelResponsePolicyConfig;
  };
};

export type SentinelConfigResponse = {
  config: SentinelConfig;
  defaults: SentinelConfig;
};

export type SentinelConfigUpdateRequest = Partial<SentinelConfig>;

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
