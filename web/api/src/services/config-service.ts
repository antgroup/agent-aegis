import { promises as fs } from "node:fs";
import path from "node:path";
import yaml from "js-yaml";
import type { AegisConfig, ConfigUpdateRequest } from "@claw-aegis-web/shared";
import { CONFIG_DEFAULTS, aegisConfigSchema } from "@claw-aegis-web/shared";

type PluginJson = {
  id: string;
  name: string;
  userConfig?: Record<string, unknown>;
  [key: string]: unknown;
};

export class ConfigService {
  private readonly configPath: string;
  private readonly isYaml: boolean;
  private lastMtime: Date | null = null;

  constructor(configDir: string) {
    // Detect environment: if config.yaml exists or AEGIS_APP=hermes, use YAML
    const yamlPath = path.join(configDir, "config.yaml");
    const jsonPath = path.join(configDir, "openclaw.plugin.json");
    
    // We check for config.yaml existence synchronously if possible, or assume based on env
    if (process.env.AEGIS_APP === "hermes") {
        this.configPath = yamlPath;
        this.isYaml = true;
    } else {
        // Default to JSON for OpenClaw, but fallback to YAML if config.yaml is present
        this.configPath = jsonPath;
        this.isYaml = false;
    }
  }

  getConfigPath(): string {
    return this.configPath;
  }

  async getConfigMtime(): Promise<string | null> {
    try {
      const stat = await fs.stat(this.configPath);
      this.lastMtime = stat.mtime;
      return stat.mtime.toISOString();
    } catch {
      return null;
    }
  }

  private async readConfigRaw(): Promise<Record<string, unknown>> {
    const raw = await fs.readFile(this.configPath, "utf8");
    if (this.isYaml) {
        return (yaml.load(raw) as Record<string, unknown>) ?? {};
    } else {
        const json = JSON.parse(raw) as PluginJson;
        return (json.userConfig as Record<string, unknown>) ?? {};
    }
  }

  private async writeConfigRaw(userConfig: Record<string, unknown>): Promise<void> {
    const dir = path.dirname(this.configPath);
    await fs.mkdir(dir, { recursive: true });
    const tempPath = `${this.configPath}.${process.pid}.${Date.now()}.tmp`;
    
    try {
      if (this.isYaml) {
          await fs.writeFile(tempPath, yaml.dump(userConfig, { indent: 2 }), "utf8");
      } else {
          const pluginJson = await this.readPluginJsonFile();
          pluginJson.userConfig = userConfig;
          await fs.writeFile(tempPath, JSON.stringify(pluginJson, null, 2) + "\n", "utf8");
      }
      await fs.rename(tempPath, this.configPath);
    } finally {
      await fs.rm(tempPath, { force: true }).catch(() => undefined);
    }
  }

  private async readPluginJsonFile(): Promise<PluginJson> {
    const raw = await fs.readFile(this.configPath, "utf8");
    return JSON.parse(raw) as PluginJson;
  }

  async getUserConfig(): Promise<Record<string, unknown>> {
    try {
      return await this.readConfigRaw();
    } catch {
      return {};
    }
  }

  resolveConfig(userConfig: Record<string, unknown>): AegisConfig {
    const allDefensesEnabled = userConfig.allDefensesEnabled !== false;

    const raw = userConfig;
    const isMode = (v: unknown): v is "off" | "observe" | "enforce" =>
      typeof v === "string" && ["off", "observe", "enforce"].includes(v);

    const defaultMode = isMode(raw.defaultBlockingMode)
      ? raw.defaultBlockingMode
      : CONFIG_DEFAULTS.defaultBlockingMode;

    const readEnabled = (key: string) =>
      allDefensesEnabled && raw[key] !== false;

    const readMode = (enabledKey: string, modeKey: string): "off" | "observe" | "enforce" => {
      if (!allDefensesEnabled || raw[enabledKey] === false) return "off";
      const explicit = raw[modeKey];
      return isMode(explicit) ? explicit : defaultMode;
    };

    return {
      allDefensesEnabled,
      defaultBlockingMode: defaultMode,
      selfProtectionEnabled: readMode("selfProtectionEnabled", "selfProtectionMode") !== "off",
      selfProtectionMode: readMode("selfProtectionEnabled", "selfProtectionMode"),
      commandBlockEnabled: readMode("commandBlockEnabled", "commandBlockMode") !== "off",
      commandBlockMode: readMode("commandBlockEnabled", "commandBlockMode"),
      encodingGuardEnabled: readMode("encodingGuardEnabled", "encodingGuardMode") !== "off",
      encodingGuardMode: readMode("encodingGuardEnabled", "encodingGuardMode"),
      scriptProvenanceGuardEnabled: readMode("scriptProvenanceGuardEnabled", "scriptProvenanceGuardMode") !== "off",
      scriptProvenanceGuardMode: readMode("scriptProvenanceGuardEnabled", "scriptProvenanceGuardMode"),
      memoryGuardEnabled: readMode("memoryGuardEnabled", "memoryGuardMode") !== "off",
      memoryGuardMode: readMode("memoryGuardEnabled", "memoryGuardMode"),
      userRiskScanEnabled: readEnabled("userRiskScanEnabled"),
      skillScanEnabled: readEnabled("skillScanEnabled"),
      toolResultScanEnabled: readEnabled("toolResultScanEnabled"),
      outputRedactionEnabled: readEnabled("outputRedactionEnabled"),
      promptGuardEnabled: readEnabled("promptGuardEnabled"),
      loopGuardEnabled: readMode("loopGuardEnabled", "loopGuardMode") !== "off",
      loopGuardMode: readMode("loopGuardEnabled", "loopGuardMode"),
      exfiltrationGuardEnabled: readMode("exfiltrationGuardEnabled", "exfiltrationGuardMode") !== "off",
      exfiltrationGuardMode: readMode("exfiltrationGuardEnabled", "exfiltrationGuardMode"),
      toolCallEnforcementEnabled: readEnabled("toolCallEnforcementEnabled"),
      dispatchGuardEnabled: readMode("dispatchGuardEnabled", "dispatchGuardMode") !== "off",
      dispatchGuardMode: readMode("dispatchGuardEnabled", "dispatchGuardMode"),
      protectedPaths: normalizeStringArray(raw.protectedPaths),
      protectedSkills: normalizeStringArray(raw.protectedSkills),
      protectedPlugins: normalizeStringArray(raw.protectedPlugins),
      startupSkillScan: raw.startupSkillScan !== false,
      webUiEnabled: raw.webUiEnabled !== false,
      webUiPort: typeof raw.webUiPort === "number" ? raw.webUiPort : CONFIG_DEFAULTS.webUiPort,
    };
  }

  async getResolvedConfig(): Promise<AegisConfig> {
    const userConfig = await this.getUserConfig();
    return this.resolveConfig(userConfig);
  }

  async updateConfig(update: ConfigUpdateRequest): Promise<AegisConfig> {
    const parsed = aegisConfigSchema.parse(update);
    const current = await this.getUserConfig();

    const merged: Record<string, unknown> = { ...current };
    for (const [key, value] of Object.entries(parsed)) {
      if (value !== undefined) {
        merged[key] = value;
      }
    }

    await this.writeConfigRaw(merged);
    return this.resolveConfig(merged);
  }

  async resetConfig(): Promise<AegisConfig> {
    await this.writeConfigRaw({});
    return this.resolveConfig({});
  }
}

function normalizeStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .filter((item): item is string => typeof item === "string")
    .map((s) => s.trim())
    .filter(Boolean);
}
