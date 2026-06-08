import { promises as fs } from "node:fs";
import path from "node:path";
import {
  TRUSTED_SKILLS_FILENAME,
  SELF_INTEGRITY_FILENAME,
  DEFENSE_EVENTS_FILENAME,
  SKILL_SCAN_EVENTS_FILENAME,
} from "@agent-aegis-web/shared";
import type { TrustedSkillInfo, SelfIntegrityStatus } from "@agent-aegis-web/shared";

type PersistedTrustedSkillsFile = {
  version: number;
  records: TrustedSkillInfo[];
};

type SelfIntegrityRecord = {
  pluginId: string;
  stateDir: string;
  protectedRoots: string[];
  fingerprints: Record<string, string>;
  updatedAt: number;
};

export class StateService {
  private readonly stateDir: string;

  constructor(stateDir: string) {
    this.stateDir = stateDir;
  }

  getStateDir(): string {
    return this.stateDir;
  }

  isConfigured(): boolean {
    return this.stateDir.length > 0;
  }

  getTrustedSkillsPath(): string {
    return path.join(this.stateDir, TRUSTED_SKILLS_FILENAME);
  }

  getSelfIntegrityPath(): string {
    return path.join(this.stateDir, SELF_INTEGRITY_FILENAME);
  }

  getDefenseEventsPath(): string {
    return path.join(this.stateDir, DEFENSE_EVENTS_FILENAME);
  }

  getSkillScanEventsPath(): string {
    return path.join(this.stateDir, SKILL_SCAN_EVENTS_FILENAME);
  }

  async getTrustedSkills(): Promise<TrustedSkillInfo[]> {
    if (!this.isConfigured()) return [];
    try {
      const raw = await fs.readFile(this.getTrustedSkillsPath(), "utf8");
      const parsed = JSON.parse(raw) as PersistedTrustedSkillsFile;
      if (!Array.isArray(parsed?.records)) return [];
      return parsed.records.filter(
        (r) =>
          typeof r.path === "string" &&
          typeof r.hash === "string" &&
          typeof r.size === "number" &&
          typeof r.scannedAt === "number",
      );
    } catch {
      return [];
    }
  }

  async removeTrustedSkill(skillPath: string): Promise<boolean> {
    if (!this.isConfigured()) return false;
    try {
      const raw = await fs.readFile(this.getTrustedSkillsPath(), "utf8");
      const parsed = JSON.parse(raw) as PersistedTrustedSkillsFile;
      if (!Array.isArray(parsed?.records)) return false;

      const normalizedTarget = path.resolve(skillPath);
      const before = parsed.records.length;
      parsed.records = parsed.records.filter(
        (r) => path.resolve(r.path) !== normalizedTarget,
      );
      if (parsed.records.length === before) return false;

      const tempPath = `${this.getTrustedSkillsPath()}.${process.pid}.${Date.now()}.tmp`;
      try {
        await fs.writeFile(tempPath, JSON.stringify(parsed, null, 2) + "\n", "utf8");
        await fs.rename(tempPath, this.getTrustedSkillsPath());
      } finally {
        await fs.rm(tempPath, { force: true }).catch(() => undefined);
      }
      return true;
    } catch {
      return false;
    }
  }

  async getSelfIntegrity(): Promise<SelfIntegrityStatus> {
    if (!this.isConfigured()) return null;
    try {
      const raw = await fs.readFile(this.getSelfIntegrityPath(), "utf8");
      const parsed = JSON.parse(raw) as SelfIntegrityRecord;
      if (
        typeof parsed?.pluginId !== "string" ||
        typeof parsed?.stateDir !== "string" ||
        typeof parsed?.updatedAt !== "number"
      ) {
        return null;
      }
      return {
        valid: true,
        protectedRoots: Array.isArray(parsed.protectedRoots)
          ? parsed.protectedRoots.filter((r): r is string => typeof r === "string")
          : [],
        fingerprintCount: parsed.fingerprints
          ? Object.keys(parsed.fingerprints).length
          : 0,
        updatedAt: parsed.updatedAt,
      };
    } catch {
      return null;
    }
  }
}
