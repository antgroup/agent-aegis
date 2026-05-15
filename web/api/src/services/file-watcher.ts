import { watch, type FSWatcher } from "chokidar";
import path from "node:path";
import { promises as fs } from "node:fs";
import {
  DEFENSE_EVENTS_FILENAME,
  SKILL_SCAN_EVENTS_FILENAME,
} from "@claw-aegis-web/shared";
import type { SecurityEvent, SkillScanEvent } from "@claw-aegis-web/shared";
import type { ConfigService } from "./config-service.js";
import type { StateService } from "./state-service.js";
import type { EventService } from "./event-service.js";
import type { SkillScanEventService } from "./skill-scan-event-service.js";

type RawDefenseEvent = {
  timestamp: number;
  defense: string;
  result: "blocked" | "observed";
  toolName?: string;
  reason?: string;
  details?: Record<string, unknown>;
  commandText?: string;
  toolParams?: Record<string, unknown>;
  userInput?: string;
};

type RawSkillScanEvent = {
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

function isValidResult(v: unknown): v is SecurityEvent["result"] {
  return v === "blocked" || v === "observed" || v === "clear";
}

export class FileWatcher {
  private watcher: FSWatcher | null = null;
  private eventsFileOffset = 0;
  private skillScanEventsFileOffset = 0;

  constructor(
    private readonly configService: ConfigService,
    private readonly stateService: StateService,
    private readonly eventService: EventService,
    private readonly skillScanEventService: SkillScanEventService,
  ) {}

  async start(): Promise<void> {
    const paths: string[] = [this.configService.getConfigPath()];

    if (this.stateService.isConfigured()) {
      paths.push(
        this.stateService.getTrustedSkillsPath(),
        this.stateService.getSelfIntegrityPath(),
        this.stateService.getDefenseEventsPath(),
        this.stateService.getSkillScanEventsPath(),
      );

      await this.loadExistingEvents();
      await this.loadExistingSkillScanEvents();
    }

    this.watcher = watch(paths, {
      ignoreInitial: true,
      awaitWriteFinish: { stabilityThreshold: 300 },
    });

    this.watcher.on("change", (filePath: string) => {
      const basename = path.basename(filePath);
      if (basename === "openclaw.plugin.json") {
        this.eventService.addEvent({
          timestamp: Date.now(),
          defense: "config",
          result: "clear",
          reason: "Configuration file changed externally",
        });
      } else if (basename === "trusted-skills.json") {
        this.eventService.addEvent({
          timestamp: Date.now(),
          defense: "skillScan",
          result: "clear",
          reason: "Trusted skills file updated",
        });
      } else if (basename === "self-integrity.json") {
        this.eventService.addEvent({
          timestamp: Date.now(),
          defense: "selfProtection",
          result: "clear",
          reason: "Self-integrity record updated",
        });
      } else if (basename === DEFENSE_EVENTS_FILENAME) {
        this.readNewEvents().catch(() => {});
      } else if (basename === SKILL_SCAN_EVENTS_FILENAME) {
        this.readNewSkillScanEvents().catch(() => {});
      }
    });
  }

  stop(): void {
    this.watcher?.close();
    this.watcher = null;
  }

  private async loadExistingEvents(): Promise<void> {
    const eventsPath = this.stateService.getDefenseEventsPath();
    try {
      const content = await fs.readFile(eventsPath, "utf8");
      this.eventsFileOffset = Buffer.byteLength(content, "utf8");
      const lines = content.trim().split("\n").filter(Boolean);
      // Load only last 1000 lines
      const recent = lines.slice(-1000);
      for (const line of recent) {
        const event = this.parseLine(line);
        if (event) {
          this.eventService.addEvent(event);
        }
      }
    } catch {
      this.eventsFileOffset = 0;
    }
  }

  private async readNewEvents(): Promise<void> {
    const eventsPath = this.stateService.getDefenseEventsPath();
    try {
      const stat = await fs.stat(eventsPath);
      if (stat.size <= this.eventsFileOffset) return;

      const fd = await fs.open(eventsPath, "r");
      try {
        const buf = Buffer.alloc(stat.size - this.eventsFileOffset);
        await fd.read(buf, 0, buf.length, this.eventsFileOffset);
        this.eventsFileOffset = stat.size;
        const chunk = buf.toString("utf8");
        const lines = chunk.trim().split("\n").filter(Boolean);
        for (const line of lines) {
          const event = this.parseLine(line);
          if (event) {
            this.eventService.addEvent(event);
          }
        }
      } finally {
        await fd.close();
      }
    } catch {
      // ignore read errors
    }
  }

  private parseLine(line: string): Omit<SecurityEvent, "id"> | null {
    try {
      const raw = JSON.parse(line) as RawDefenseEvent;
      if (typeof raw.timestamp !== "number" || typeof raw.defense !== "string" || !isValidResult(raw.result)) {
        return null;
      }
      return {
        timestamp: raw.timestamp,
        defense: raw.defense,
        result: raw.result,
        toolName: raw.toolName,
        reason: raw.reason,
        details: raw.details,
        commandText: raw.commandText,
        toolParams: raw.toolParams,
        userInput: raw.userInput,
      };
    } catch {
      return null;
    }
  }

  private async loadExistingSkillScanEvents(): Promise<void> {
    const eventsPath = this.stateService.getSkillScanEventsPath();
    try {
      const content = await fs.readFile(eventsPath, "utf8");
      this.skillScanEventsFileOffset = Buffer.byteLength(content, "utf8");
      const lines = content.trim().split("\n").filter(Boolean);
      const recent = lines.slice(-1000);
      for (const line of recent) {
        const event = this.parseSkillScanLine(line);
        if (event) {
          this.skillScanEventService.addEvent(event);
        }
      }
    } catch {
      this.skillScanEventsFileOffset = 0;
    }
  }

  private async readNewSkillScanEvents(): Promise<void> {
    const eventsPath = this.stateService.getSkillScanEventsPath();
    try {
      const stat = await fs.stat(eventsPath);
      if (stat.size <= this.skillScanEventsFileOffset) return;

      const fd = await fs.open(eventsPath, "r");
      try {
        const buf = Buffer.alloc(stat.size - this.skillScanEventsFileOffset);
        await fd.read(buf, 0, buf.length, this.skillScanEventsFileOffset);
        this.skillScanEventsFileOffset = stat.size;
        const chunk = buf.toString("utf8");
        const lines = chunk.trim().split("\n").filter(Boolean);
        for (const line of lines) {
          const event = this.parseSkillScanLine(line);
          if (event) {
            this.skillScanEventService.addEvent(event);
          }
        }
      } finally {
        await fd.close();
      }
    } catch {
      // ignore read errors
    }
  }

  private parseSkillScanLine(line: string): Omit<SkillScanEvent, "id"> | null {
    try {
      const raw = JSON.parse(line) as RawSkillScanEvent;
      if (
        typeof raw.timestamp !== "number" ||
        typeof raw.skillId !== "string" ||
        typeof raw.path !== "string"
      ) {
        return null;
      }
      return {
        timestamp: raw.timestamp,
        skillId: raw.skillId,
        path: raw.path,
        hash: raw.hash,
        size: raw.size,
        sourceRoot: raw.sourceRoot,
        trusted: !!raw.trusted,
        findings: Array.isArray(raw.findings) ? raw.findings : [],
        phase: raw.phase ?? "unknown",
      };
    } catch {
      return null;
    }
  }
}
