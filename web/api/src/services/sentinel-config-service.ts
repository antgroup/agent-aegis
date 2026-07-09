import { promises as fs } from "node:fs";
import path from "node:path";
import os from "node:os";
import type {
  SentinelConfig,
  SentinelConfigUpdateRequest,
} from "@agent-aegis-web/shared";
import {
  SENTINEL_CONFIG_DEFAULTS,
  sentinelConfigSchema,
} from "@agent-aegis-web/shared";

function expandHome(p: string): string {
  return p.startsWith("~") ? path.join(os.homedir(), p.slice(1)) : p;
}

/**
 * Reads/writes ONE per-agent sentinel (L2/L3) JSON config file, independent of
 * the L1 ConfigService. Path comes from AEGIS_SENTINEL_CONFIG (e.g.
 * ~/.openclaw/agent-aegis-sentinel/config.json). The sidecar reads this file at
 * startup, so edits take effect on the next sidecar restart (no hot reload).
 */
export class SentinelConfigService {
  private readonly configPath: string;

  constructor(configPath: string) {
    this.configPath = expandHome(configPath);
  }

  getConfigPath(): string {
    return this.configPath;
  }

  private async readRaw(): Promise<Record<string, unknown>> {
    try {
      return JSON.parse(await fs.readFile(this.configPath, "utf8")) as Record<
        string,
        unknown
      >;
    } catch {
      return {};
    }
  }

  private async writeRaw(config: Record<string, unknown>): Promise<void> {
    await fs.mkdir(path.dirname(this.configPath), { recursive: true });
    const tmp = `${this.configPath}.${process.pid}.${Date.now()}.tmp`;
    try {
      await fs.writeFile(tmp, JSON.stringify(config, null, 2) + "\n", "utf8");
      await fs.rename(tmp, this.configPath);
    } finally {
      await fs.rm(tmp, { force: true }).catch(() => undefined);
    }
  }

  private resolve(raw: Record<string, unknown>): SentinelConfig {
    const nj = (raw.nativeJudge ?? {}) as Record<string, unknown>;
    const pr = (raw.probes ?? {}) as Record<string, unknown>;
    const ebpf = (pr.ebpf ?? {}) as Record<string, unknown>;
    const uprobe = (pr.uprobe ?? {}) as Record<string, unknown>;
    const lsm = (pr.lsm ?? {}) as Record<string, unknown>;
    const sentinel = (raw.sentinel ?? {}) as Record<string, unknown>;
    const behaviorJudge = (sentinel.behaviorJudge ?? {}) as Record<string, unknown>;
    const responsePolicy = (sentinel.responsePolicy ?? {}) as Record<string, unknown>;
    const arr = (v: unknown): string[] =>
      Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
    const num01 = (v: unknown, fallback: number): number =>
      typeof v === "number" && Number.isFinite(v) && v >= 0 && v <= 1
        ? v
        : fallback;
    const severity = (
      v: unknown,
      fallback: SentinelConfig["sentinel"]["responsePolicy"]["blockSeverity"],
    ): SentinelConfig["sentinel"]["responsePolicy"]["blockSeverity"] =>
      v === "info" || v === "low" || v === "medium" || v === "high" || v === "critical"
        ? v
        : fallback;
    return {
      stateDir:
        typeof raw.stateDir === "string"
          ? raw.stateDir
          : SENTINEL_CONFIG_DEFAULTS.stateDir,
      nativeJudge: {
        mode: nj.mode === "enforce" ? "enforce" : "observe",
        sensitivePaths: arr(nj.sensitivePaths),
        scratchDirs: arr(nj.scratchDirs),
      },
      probes: {
        ebpf: { enabled: ebpf.enabled === true },
        uprobe: { enabled: uprobe.enabled === true },
        lsm: {
          enabled: lsm.enabled === true,
          minSeverity: lsm.minSeverity === "critical" ? "critical" : "high",
        },
      },
      sentinel: {
        behaviorJudge: {
          enabled: behaviorJudge.enabled === true,
          mode:
            behaviorJudge.mode === "off" ||
            behaviorJudge.mode === "enforce" ||
            behaviorJudge.mode === "observe"
              ? behaviorJudge.mode
              : SENTINEL_CONFIG_DEFAULTS.sentinel.behaviorJudge.mode,
          minEvents:
            typeof behaviorJudge.minEvents === "number"
              ? behaviorJudge.minEvents
              : SENTINEL_CONFIG_DEFAULTS.sentinel.behaviorJudge.minEvents,
          recentCount:
            typeof behaviorJudge.recentCount === "number"
              ? behaviorJudge.recentCount
              : SENTINEL_CONFIG_DEFAULTS.sentinel.behaviorJudge.recentCount,
          rules:
            behaviorJudge.rules &&
            typeof behaviorJudge.rules === "object" &&
            !Array.isArray(behaviorJudge.rules)
              ? (behaviorJudge.rules as SentinelConfig["sentinel"]["behaviorJudge"]["rules"])
              : (SENTINEL_CONFIG_DEFAULTS.sentinel.behaviorJudge
                  .rules as SentinelConfig["sentinel"]["behaviorJudge"]["rules"]),
        },
        responsePolicy: {
          enabled: responsePolicy.enabled === true,
          mode:
            responsePolicy.mode === "off" ||
            responsePolicy.mode === "enforce" ||
            responsePolicy.mode === "observe"
              ? responsePolicy.mode
              : SENTINEL_CONFIG_DEFAULTS.sentinel.responsePolicy.mode,
          minAlertConfidence: num01(
            responsePolicy.minAlertConfidence,
            SENTINEL_CONFIG_DEFAULTS.sentinel.responsePolicy.minAlertConfidence,
          ),
          minBlockConfidence: num01(
            responsePolicy.minBlockConfidence,
            SENTINEL_CONFIG_DEFAULTS.sentinel.responsePolicy.minBlockConfidence,
          ),
          minKillConfidence: num01(
            responsePolicy.minKillConfidence,
            SENTINEL_CONFIG_DEFAULTS.sentinel.responsePolicy.minKillConfidence,
          ),
          blockSeverity: severity(
            responsePolicy.blockSeverity,
            SENTINEL_CONFIG_DEFAULTS.sentinel.responsePolicy.blockSeverity,
          ),
          killSeverity: severity(
            responsePolicy.killSeverity,
            SENTINEL_CONFIG_DEFAULTS.sentinel.responsePolicy.killSeverity,
          ),
          allowKill: responsePolicy.allowKill === true,
          allowThrottle: responsePolicy.allowThrottle === true,
          allowIsolate: responsePolicy.allowIsolate === true,
          safeAttributions: Array.isArray(responsePolicy.safeAttributions)
            ? responsePolicy.safeAttributions.filter(
                (v): v is string => typeof v === "string",
              )
            : SENTINEL_CONFIG_DEFAULTS.sentinel.responsePolicy.safeAttributions,
        },
      },
    };
  }

  async getConfig(): Promise<SentinelConfig> {
    return this.resolve(await this.readRaw());
  }

  async updateConfig(
    update: SentinelConfigUpdateRequest,
  ): Promise<SentinelConfig> {
    const parsed = sentinelConfigSchema.parse(update);
    const current = await this.readRaw();
    const merged: Record<string, unknown> = { ...current };
    for (const [k, v] of Object.entries(parsed)) {
      if (v !== undefined) merged[k] = v;
    }
    await this.writeRaw(merged);
    return this.resolve(merged);
  }

  async resetConfig(): Promise<SentinelConfig> {
    // Keep the installer-set stateDir; reset only the defense settings.
    const current = await this.readRaw();
    const kept =
      typeof current.stateDir === "string" ? { stateDir: current.stateDir } : {};
    await this.writeRaw(kept);
    return this.resolve(kept);
  }
}
