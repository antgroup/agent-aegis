import type { AegisConfig, DefenseMode } from "@agent-aegis-web/shared";
import { ToggleSwitch } from "../common/ToggleSwitch";
import { ModeSelector } from "../common/ModeSelector";
import { useTranslation } from "react-i18next";

export function MasterControls({
  config,
  onChange,
}: {
  config: AegisConfig;
  onChange: (patch: Partial<AegisConfig>) => void;
}) {
  const { t } = useTranslation();

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-5 mb-6">
      <h2 className="text-base font-semibold mb-4">{t("config.masterControls")}</h2>
      <div className="flex flex-wrap items-center gap-6">
        <ToggleSwitch
          checked={config.allDefensesEnabled}
          onChange={(v) => onChange({ allDefensesEnabled: v })}
          label={t("config.enableAllDefenses")}
        />
        <div className="flex items-center gap-2">
          <span className="text-sm text-gray-600">{t("config.defaultMode")}</span>
          <ModeSelector
            value={config.defaultBlockingMode}
            onChange={(v: DefenseMode) => onChange({ defaultBlockingMode: v })}
          />
        </div>
      </div>
    </div>
  );
}
