import express from "express";
import cors from "cors";
import path from "node:path";
import { existsSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { API_PREFIX } from "@agent-aegis-web/shared";
import { createConfigRouter } from "./routes/config.js";
import { createStatusRouter } from "./routes/status.js";
import { createEventsRouter } from "./routes/events.js";
import { createSkillsRouter } from "./routes/skills.js";
import { createSkillScansRouter } from "./routes/skill-scans.js";
import { createSentinelConfigRouter } from "./routes/sentinel-config.js";
import { ConfigService } from "./services/config-service.js";
import { SentinelConfigService } from "./services/sentinel-config-service.js";
import { StateService } from "./services/state-service.js";
import { EventService } from "./services/event-service.js";
import { SkillScanEventService } from "./services/skill-scan-event-service.js";
import { FileWatcher } from "./services/file-watcher.js";

export type ServerOptions = {
  configDir: string;
  stateDir: string;
  sentinelConfigPath: string;
};

export function createServer(options: ServerOptions) {
  const app = express();

  app.use(cors());
  app.use(express.json());

  const configService = new ConfigService(options.configDir);
  const sentinelConfigService = new SentinelConfigService(options.sentinelConfigPath);
  const stateService = new StateService(options.stateDir);
  const eventService = new EventService();
  const skillScanEventService = new SkillScanEventService();
  
  const fileWatcher = new FileWatcher(configService, stateService, eventService, skillScanEventService);

  fileWatcher.start().catch((err) =>
    console.error("[agent-aegis-web] FileWatcher start error:", err),
  );

  app.use(`${API_PREFIX}/config`, createConfigRouter(configService));
  app.use(`${API_PREFIX}/sentinel-config`, createSentinelConfigRouter(sentinelConfigService));
  app.use(`${API_PREFIX}/status`, createStatusRouter(configService, stateService));
  app.use(`${API_PREFIX}/events`, createEventsRouter(eventService));
  app.use(`${API_PREFIX}/skills`, createSkillsRouter(stateService, eventService));
  app.use(`${API_PREFIX}/skill-scans`, createSkillScansRouter(skillScanEventService));

  app.get(`${API_PREFIX}/health`, (_req, res) => {
    res.json({ 
        status: "ok", 
        version: "0.1.0",
        app: process.env.AEGIS_APP || "openclaw"
    });
  });

  // Serve frontend static files in production
  const frontendDist = process.env.AEGIS_STATIC_DIR || path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    // Support both source layout (../../frontend/dist) and installed layout (./static)
    existsSync(path.resolve(path.dirname(fileURLToPath(import.meta.url)), "./static"))
      ? "./static"
      : "../../frontend/dist",
  );
  if (existsSync(frontendDist)) {
    app.use(express.static(frontendDist));
    app.get("*", (_req, res, next) => {
      if (_req.path.startsWith(API_PREFIX)) return next();
      res.sendFile(path.join(frontendDist, "index.html"), (err) => {
        if (err) next();
      });
    });
  } else {
    console.warn(`[agent-aegis-web] Static directory not found: ${frontendDist}. Web UI may not be available.`);
  }

  // Error handler
  app.use(
    (
      err: Error,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      console.error("[agent-aegis-web] Error:", err.message);
      res.status(500).json({ ok: false, error: err.message });
    },
  );

  return { app };
}
