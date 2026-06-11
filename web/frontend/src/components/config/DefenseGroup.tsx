import type { AegisConfig, DefenseMode } from "@agent-aegis-web/shared";
import type { DefenseGroupMeta } from "@agent-aegis-web/shared";
import { ToggleSwitch } from "../common/ToggleSwitch";
import { ModeSelector } from "../common/ModeSelector";
import { useTranslation } from "react-i18next";

export function DefenseGroup({
  group,
  config,
  onChange,
}: {
  group: DefenseGroupMeta;
  config: AegisConfig;
  onChange: (patch: Partial<AegisConfig>) => void;
}) {
  const { t } = useTranslation();
  const enabled = config[group.enabledKey as keyof AegisConfig] as boolean;
  const mode = group.modeKey
    ? (config[group.modeKey as keyof AegisConfig] as DefenseMode)
    : undefined;
  const masterOff = !config.allDefensesEnabled;

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-3">
            <ToggleSwitch
              checked={enabled}
              onChange={(v) =>
                onChange({ [group.enabledKey]: v } as Partial<AegisConfig>)
              }
              disabled={masterOff}
            />
            <h3 className="text-sm font-semibold text-gray-900">
              {t(`defenseGroups.${group.id}.label`, { defaultValue: group.label })}
            </h3>
          </div>
          <p className="text-xs text-gray-500 mt-1 ml-11">
            {t(`defenseGroups.${group.id}.help`, { defaultValue: group.help })}
          </p>
        </div>
        {mode !== undefined && (
          <ModeSelector
            value={mode}
            onChange={(v) =>
              onChange({ [group.modeKey!]: v } as Partial<AegisConfig>)
            }
            disabled={masterOff || !enabled}
          />
        )}
      </div>
    </div>
  );
}
