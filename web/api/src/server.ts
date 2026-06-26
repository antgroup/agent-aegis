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

export type ServerOptions = {
  configDir: string;
  stateDir: string;
};

// Origins allowed to call the API from a browser. The bundled UI is served
// same-origin, and the Vite dev server proxies /api, so only loopback origins
// are needed by default. Extend with AEGIS_ALLOWED_ORIGINS (comma-separated).
function resolveAllowedOrigins(): string[] {
  const defaults = [
    "http://localhost:3800",
    "http://127.0.0.1:3800",
    "http://localhost:3801",
    "http://127.0.0.1:3801",
  ];
  const extra = (process.env.AEGIS_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  return [...new Set([...defaults, ...extra])];
}

// Guard the management API against unauthorized local callers. When AEGIS_TOKEN
// is set, every API request must carry the matching token. Otherwise we fall
// back to a CSRF guard: a browser cross-origin request (e.g. a malicious page
// hitting 127.0.0.1) always carries an Origin header, so we reject any Origin
// outside the allowlist. Same-origin UI calls and non-browser tools (no Origin)
// keep working. The /health probe stays open for liveness checks.
function createApiAccessGuard(opts: { allowedOrigins: string[]; token?: string }) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (req.path === "/health") return next();

    if (opts.token) {
      const provided =
        req.get("x-aegis-token") ??
        (typeof req.query.token === "string" ? req.query.token : undefined) ??
        req.get("authorization")?.replace(/^Bearer\s+/i, "");
      if (provided !== opts.token) {
        return res.status(401).json({ ok: false, error: "Unauthorized" });
      }
      return next();
    }

    const origin = req.get("origin");
    if (origin && !opts.allowedOrigins.includes(origin)) {
      return res.status(403).json({ ok: false, error: "Forbidden origin" });
    }
    return next();
  };
}

export function createServer(options: ServerOptions) {
  const app = express();

  const allowedOrigins = resolveAllowedOrigins();
  const token = process.env.AEGIS_TOKEN?.trim() || undefined;

  app.use(
    cors({
      origin(origin, callback) {
        // Allow non-browser callers (no Origin) and allowlisted origins only.
        if (!origin || allowedOrigins.includes(origin)) return callback(null, true);
        return callback(null, false);
      },
    }),
  );
  app.use(express.json());
  app.use(API_PREFIX, createApiAccessGuard({ allowedOrigins, token }));

  if (token) {
    console.log("[claw-aegis-web] API token auth enabled (AEGIS_TOKEN set).");
  }

  const configService = new ConfigService(options.configDir);
  const stateService = new StateService(options.stateDir);
  const eventService = new EventService();
  const skillScanEventService = new SkillScanEventService();
  const fileWatcher = new FileWatcher(configService, stateService, eventService, skillScanEventService);

  fileWatcher.start().catch((err) =>
    console.error("[claw-aegis-web] FileWatcher start error:", err),
  );

  app.use(`${API_PREFIX}/config`, createConfigRouter(configService));
  app.use(`${API_PREFIX}/status`, createStatusRouter(configService, stateService));
  app.use(`${API_PREFIX}/events`, createEventsRouter(eventService));
  app.use(`${API_PREFIX}/skills`, createSkillsRouter(stateService, eventService));
  app.use(`${API_PREFIX}/skill-scans`, createSkillScansRouter(skillScanEventService));

  app.get(`${API_PREFIX}/health`, (_req, res) => {
    res.json({ status: "ok", version: "0.1.0" });
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

  return app;
}
