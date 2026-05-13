import express from "express";
import cors from "cors";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { API_PREFIX } from "@claw-aegis-web/shared";
import { createConfigRouter } from "./routes/config.js";
import { createStatusRouter } from "./routes/status.js";
import { createEventsRouter } from "./routes/events.js";
import { createSkillsRouter } from "./routes/skills.js";
import { createSkillScansRouter } from "./routes/skill-scans.js";
import { ConfigService } from "./services/config-service.js";
import { StateService } from "./services/state-service.js";
import { EventService } from "./services/event-service.js";
import { SkillScanEventService } from "./services/skill-scan-event-service.js";
import { FileWatcher } from "./services/file-watcher.js";
import { AegisRpcClient } from "./services/rpc-client.js";

export type ServerOptions = {
  configDir: string;
  stateDir: string;
  rpcServerPath?: string;
};

export function createServer(options: ServerOptions) {
  const app = express();

  app.use(cors());
  app.use(express.json());

  const configService = new ConfigService(options.configDir);
  const stateService = new StateService(options.stateDir);
  const eventService = new EventService();
  const skillScanEventService = new SkillScanEventService();
  
  // Optional RPC client for Hermes
  const rpcClient = options.rpcServerPath ? new AegisRpcClient(options.rpcServerPath) : undefined;
  let rpcInitialized = false;

  const fileWatcher = new FileWatcher(configService, stateService, eventService, skillScanEventService);

  fileWatcher.start().catch((err) =>
    console.error("[claw-aegis-web] FileWatcher start error:", err),
  );

  if (rpcClient) {
      async function initRpc() {
          try {
              rpcClient!.start();
              await new Promise((resolve) => setTimeout(resolve, 500));
              const config = await configService.getUserConfig();
              // For Hermes, pluginRootDir is 2 levels up from configDir
              const pluginRootDir = path.resolve(options.configDir, "..", "..");
              await rpcClient!.init({
                  config,
                  stateDir: options.stateDir,
                  pluginRootDir,
              });
              rpcInitialized = true;
              console.log("[claw-aegis-web] RPC client initialized successfully");
          } catch (err) {
              console.error("[claw-aegis-web] RPC initialization failed:", err instanceof Error ? err.message : String(err));
          }
      }
      initRpc();
  }

  app.use(`${API_PREFIX}/config`, createConfigRouter(configService));
  app.use(`${API_PREFIX}/status`, createStatusRouter(configService, stateService));
  app.use(`${API_PREFIX}/events`, createEventsRouter(eventService));
  app.use(`${API_PREFIX}/skills`, createSkillsRouter(stateService, eventService));
  app.use(`${API_PREFIX}/skill-scans`, createSkillScansRouter(skillScanEventService));

  app.get(`${API_PREFIX}/health`, (_req, res) => {
    res.json({ 
        status: "ok", 
        version: "0.1.0",
        app: process.env.AEGIS_APP || "openclaw",
        rpc: rpcClient ? { connected: rpcClient.isReady(), initialized: rpcInitialized } : undefined
    });
  });

  // RPC status endpoint
  app.get(`${API_PREFIX}/rpc/status`, (_req, res) => {
    if (!rpcClient) return res.status(404).json({ ok: false, error: "RPC not enabled" });
    res.json({
      ok: true,
      data: {
        connected: rpcClient.isReady(),
        initialized: rpcInitialized,
      },
    });
  });

  // Serve frontend static files in production
  const frontendDist = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../../frontend/dist",
  );
  app.use(express.static(frontendDist));
  app.get("*", (_req, res, next) => {
    if (_req.path.startsWith(API_PREFIX)) return next();
    res.sendFile(path.join(frontendDist, "index.html"), (err) => {
      if (err) next();
    });
  });

  // Error handler
  app.use(
    (
      err: Error,
      _req: express.Request,
      res: express.Response,
      _next: express.NextFunction,
    ) => {
      console.error("[claw-aegis-web] Error:", err.message);
      res.status(500).json({ ok: false, error: err.message });
    },
  );

  return { app, rpcClient };
}
