export type AgentHazardCategory =
  | "Compliance_Bypass"
  | "Data_Exfiltration"
  | "Destructive_Action"
  | "Internal_Reconnaissance"
  | "Persistence_Establishment"
  | "Privilege_Escalation"
  | "Prompt_Intel_Theft"
  | "Resource_Exhaustion"
  | "Supply_Chain_Poisoning"
  | "System_RCE";

export type AgentHazardJailbreakMethod =
  | "Contextual_Persona_Enforcement"
  | "Dependency_Hook_Trigger"
  | "Direct"
  | "Encoded_Payload_Smuggling"
  | "Implicit_Indirect_Injection"
  | "Legacy_Code_Maintenance"
  | "Logical_Dependency_Inversion"
  | "Pseudo_Diagnostic_Debugging"
  | "Recursive_Salami_Slicing"
  | "Security_Audit_Gaslighting";

export interface AgentHazardInstance {
  id: number;
  category: AgentHazardCategory;
  jailbreak_method: AgentHazardJailbreakMethod;
  query: string;
  decomposed_query: string[];
  comment: string;
  source: string;
  original_id?: number;
}

export interface CategoryMapping {
  category: AgentHazardCategory;
  expectedSignals: string[];
  expectedSnapshotFields: string[];
  expectedCausalChains: string[];
  knownGaps: string[];
}

export interface SamplingOptions {
  perCategory: number;
  seed: number;
  categories?: AgentHazardCategory[];
  jailbreakMethods?: AgentHazardJailbreakMethod[];
}

export interface SampledInstance extends AgentHazardInstance {
  sampleRank: number;
  stratumKey: string;
}

export interface DatasetSummary {
  total: number;
  selected: number;
  byCategory: Record<string, number>;
  byJailbreakMethod: Record<string, number>;
  byStratum: Record<string, number>;
  selectedByCategory: Record<string, number>;
  selectedByJailbreakMethod: Record<string, number>;
  selectedByStratum: Record<string, number>;
}

export interface DryRunReport {
  generatedAt: string;
  datasetPath: string;
  options: SamplingOptions;
  summary: DatasetSummary;
  selected: SampledInstance[];
}

export interface BenchRunArgs {
  dataset: string;
  out: string;
  samplePerCategory: number;
  seed: number;
  dryRun: boolean;
  categories?: AgentHazardCategory[];
  jailbreakMethods?: AgentHazardJailbreakMethod[];
}

export const AGENTHAZARD_CATEGORIES: readonly AgentHazardCategory[] = [
  "Compliance_Bypass",
  "Data_Exfiltration",
  "Destructive_Action",
  "Internal_Reconnaissance",
  "Persistence_Establishment",
  "Privilege_Escalation",
  "Prompt_Intel_Theft",
  "Resource_Exhaustion",
  "Supply_Chain_Poisoning",
  "System_RCE",
];

export const AGENTHAZARD_JAILBREAK_METHODS: readonly AgentHazardJailbreakMethod[] = [
  "Contextual_Persona_Enforcement",
  "Dependency_Hook_Trigger",
  "Direct",
  "Encoded_Payload_Smuggling",
  "Implicit_Indirect_Injection",
  "Legacy_Code_Maintenance",
  "Logical_Dependency_Inversion",
  "Pseudo_Diagnostic_Debugging",
  "Recursive_Salami_Slicing",
  "Security_Audit_Gaslighting",
];
