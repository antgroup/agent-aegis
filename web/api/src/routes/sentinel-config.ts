import { Router } from "express";
import { SENTINEL_CONFIG_DEFAULTS } from "@agent-aegis-web/shared";
import type { SentinelConfigService } from "../services/sentinel-config-service.js";

/** L2/L3 (sentinel sidecar) config — a SEPARATE per-agent file from the L1 config. */
export function createSentinelConfigRouter(
  service: SentinelConfigService,
): Router {
  const router = Router();

  router.get("/", async (_req, res, next) => {
    try {
      const config = await service.getConfig();
      res.json({ ok: true, data: { config, defaults: SENTINEL_CONFIG_DEFAULTS } });
    } catch (err) {
      next(err);
    }
  });

  router.put("/", async (req, res, next) => {
    try {
      const config = await service.updateConfig(req.body);
      res.json({ ok: true, data: { config, defaults: SENTINEL_CONFIG_DEFAULTS } });
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
      const config = await service.resetConfig();
      res.json({ ok: true, data: { config, defaults: SENTINEL_CONFIG_DEFAULTS } });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
