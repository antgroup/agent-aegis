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
    const arr = (v: unknown): string[] =>
      Array.isArray(v) ? v.filter((x): x is string => typeof x === "string") : [];
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
