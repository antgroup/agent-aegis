import express from "express";
import cors from "cors";
import path from "node:path";
import fs from "node:fs";
import crypto from "node:crypto";
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
// are needed by default. Derived from the configured port (and port+1 for the
// Vite dev server) so a custom AEGIS_PORT does not break the UI. Extend with
// AEGIS_ALLOWED_ORIGINS (comma-separated).
function resolveAllowedOrigins(): string[] {
  const apiPort = parseInt(process.env.AEGIS_PORT ?? "3800", 10);
  const devPort = apiPort + 1;
  const defaults = [apiPort, devPort].flatMap((p) => [
    `http://localhost:${p}`,
    `http://127.0.0.1:${p}`,
  ]);
  const extra = (process.env.AEGIS_ALLOWED_ORIGINS ?? "")
    .split(",")
    .map((value) => value.trim())
    .filter(Boolean);
  return [...new Set([...defaults, ...extra])];
}

// Resolve the API token. Priority: AEGIS_TOKEN (provided out-of-band — the
// strongest mode, never written anywhere) > a persisted per-install token >
// a freshly generated one written to a 0600 file. The file lets the same
// machine's UI/CLI reuse the token across restarts; for a hardened setup,
// place AEGIS_CONFIG_DIR (and thus this file) inside an agent-aegis protected
// path so a compromised local agent cannot read it.
function resolveApiToken(configDir: string): { token: string; fromEnv: boolean } {
  const fromEnv = process.env.AEGIS_TOKEN?.trim();
  if (fromEnv) return { token: fromEnv, fromEnv: true };

  const tokenFile = path.join(configDir, ".aegis-webui-token");
  try {
    const existing = fs.readFileSync(tokenFile, "utf8").trim();
    if (existing) return { token: existing, fromEnv: false };
  } catch {
    /* not yet created */
  }
  const token = crypto.randomBytes(24).toString("hex");
  try {
    fs.writeFileSync(tokenFile, token + "\n", { mode: 0o600 });
    fs.chmodSync(tokenFile, 0o600);
  } catch (err) {
    console.error("[claw-aegis-web] could not persist token file:", err);
  }
  return { token, fromEnv: false };
}

// Guard state-changing API requests (PUT/POST/DELETE/PATCH) with the token.
// This blocks the confused-deputy vector where a non-browser local caller
// (e.g. a prompt-injected agent issuing a plain HTTP PUT) rewrites the
// agent-aegis-protected manifest through the WebUI. Read-only GETs stay open
// so the UI loads without friction; cross-origin browser reads are already
// blocked by the CORS allowlist. /health stays open for liveness checks.
// Constant-time token comparison to avoid leaking the token via response timing.
function tokensMatch(provided: string | undefined, expected: string): boolean {
  if (!provided) return false;
  const a = Buffer.from(provided);
  const b = Buffer.from(expected);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

const MUTATING_METHODS = new Set(["POST", "PUT", "DELETE", "PATCH"]);
function createApiAccessGuard(token: string) {
  return (req: express.Request, res: express.Response, next: express.NextFunction) => {
    if (req.path === "/health") return next();
    if (!MUTATING_METHODS.has(req.method)) return next();

    const provided =
      req.get("x-aegis-token") ??
      (typeof req.query.token === "string" ? req.query.token : undefined) ??
      req.get("authorization")?.replace(/^Bearer\s+/i, "");
    if (!tokensMatch(provided, token)) {
      return res.status(401).json({ ok: false, error: "Unauthorized" });
    }
    return next();
  };
}

export function createServer(options: ServerOptions) {
  const app = express();

  const allowedOrigins = resolveAllowedOrigins();
  const { token, fromEnv } = resolveApiToken(options.configDir);

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
  app.use(API_PREFIX, createApiAccessGuard(token));

  // Hardened mode: when the token is provided out-of-band via AEGIS_TOKEN we do
  // NOT serve it to clients (see serveIndex below) so a local agent cannot read
  // it from the page. The operator enters it into the UI once. In default mode
  // the auto-generated token is injected for zero-friction local use.
  const injectToken = !fromEnv;
  console.log(
    fromEnv
      ? "[claw-aegis-web] API write auth: token required (from AEGIS_TOKEN). " +
          "Token is NOT served to the UI; enter it in the UI when prompted."
      : `[claw-aegis-web] API write auth: token required. Token: ${token}`,
  );

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

  // Serve frontend static files in production. In default mode the SPA shell
  // (index.html) is served via a handler that injects the auto-generated token
  // as a meta tag so the same-origin UI authenticates its writes with no setup.
  // In hardened mode (AEGIS_TOKEN set) the token is NOT injected; the UI prompts
  // the operator for it. Static assets are served directly.
  const frontendDist = path.resolve(
    path.dirname(fileURLToPath(import.meta.url)),
    "../../frontend/dist",
  );
  const serveIndex = (_req: express.Request, res: express.Response, next: express.NextFunction) => {
    let html: string;
    try {
      html = fs.readFileSync(path.join(frontendDist, "index.html"), "utf8");
    } catch {
      return next();
    }
    if (injectToken) {
      const meta = `<meta name="aegis-token" content="${token}">`;
      html = html.includes("</head>") ? html.replace("</head>", `${meta}</head>`) : `${meta}${html}`;
    }
    res.type("html").send(html);
  };
  app.use(express.static(frontendDist, { index: false }));
  app.get("*", (req, res, next) => {
    if (req.path.startsWith(API_PREFIX)) return next();
    return serveIndex(req, res, next);
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
