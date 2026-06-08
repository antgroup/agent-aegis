import { Router } from "express";
import { CONFIG_DEFAULTS } from "@agent-aegis-web/shared";
import type { ConfigService } from "../services/config-service.js";

export function createConfigRouter(configService: ConfigService): Router {
  const router = Router();

  router.get("/", async (_req, res, next) => {
    try {
      const [config, mtime] = await Promise.all([
        configService.getResolvedConfig(),
        configService.getConfigMtime(),
      ]);
      res.json({ ok: true, data: { config, defaults: CONFIG_DEFAULTS } });
    } catch (err) {
      next(err);
    }
  });

  router.put("/", async (req, res, next) => {
    try {
      const config = await configService.updateConfig(req.body);
      res.json({ ok: true, data: { config, defaults: CONFIG_DEFAULTS } });
    } catch (err) {
      if (err instanceof Error && err.name === "ZodError") {
        res.status(400).json({ ok: false, error: err.message });
        return;
      }
      next(err);
    }
  });

  router.post("/reset", async (_req, res, next) => {
    try {
      const config = await configService.resetConfig();
      res.json({ ok: true, data: { config, defaults: CONFIG_DEFAULTS } });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
