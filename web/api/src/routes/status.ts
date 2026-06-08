import { Router } from "express";
import { DEFENSE_GROUPS } from "@agent-aegis-web/shared";
import type { DefenseStatusEntry, StatusResponse } from "@agent-aegis-web/shared";
import type { ConfigService } from "../services/config-service.js";
import type { StateService } from "../services/state-service.js";

export function createStatusRouter(
  configService: ConfigService,
  stateService: StateService,
): Router {
  const router = Router();

  router.get("/", async (_req, res, next) => {
    try {
      const [config, integrity, trustedSkills, mtime] = await Promise.all([
        configService.getResolvedConfig(),
        stateService.getSelfIntegrity(),
        stateService.getTrustedSkills(),
        configService.getConfigMtime(),
      ]);

      const defenses: DefenseStatusEntry[] = DEFENSE_GROUPS.map((group) => {
        const enabledKey = group.enabledKey as keyof typeof config;
        const modeKey = group.modeKey as keyof typeof config | undefined;
        return {
          id: group.id,
          label: group.label,
          help: group.help,
          enabled: Boolean(config[enabledKey]),
          mode: modeKey ? (config[modeKey] as DefenseStatusEntry["mode"]) : undefined,
        };
      });

      const status: StatusResponse = {
        defenses,
        integrity,
        trustedSkillCount: trustedSkills.length,
        configMtime: mtime,
      };

      res.json({ ok: true, data: status });
    } catch (err) {
      next(err);
    }
  });

  return router;
}
