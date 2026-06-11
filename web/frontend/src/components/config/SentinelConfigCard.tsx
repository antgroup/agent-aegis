import type { SentinelConfig } from "@agent-aegis-web/shared";
import { ToggleSwitch } from "../common/ToggleSwitch";
import { ArrayEditor } from "./ArrayEditor";
import { Save } from "lucide-react";
import { clsx } from "clsx";
import { useTranslation } from "react-i18next";

/**
 * L2/L3 kernel-defense (sentinel sidecar) config card. Edits a SEPARATE
 * per-agent config file from the L1 defenses; changes apply on sidecar restart.
 */
export function SentinelConfigCard({
  config,
  isDirty,
  isPending,
  onChange,
  onSave,
}: {
  config: SentinelConfig;
  isDirty: boolean;
  isPending: boolean;
  onChange: (partial: Partial<SentinelConfig>) => void;
  onSave: () => void;
}) {
  const { t } = useTranslation();
  const nj = config.nativeJudge;
  const pr = config.probes;

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6 space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <h3 className="text-sm font-semibold text-gray-900">{t("config.nativeJudgeMode")}</h3>
          <p className="text-xs text-gray-500 mt-0.5">{t("config.kernelDefenseHelp")}</p>
        </div>
        <div className="flex items-center gap-3">
          {isDirty && (
            <span className="text-xs text-amber-600 font-medium">{t("config.unsavedChanges")}</span>
          )}
          <div className="inline-flex rounded-md border border-gray-300 overflow-hidden">
            {(["observe", "enforce"] as const).map((m) => (
              <button
                key={m}
                type="button"
                onClick={() => onChange({ nativeJudge: { ...nj, mode: m } })}
                className={clsx(
                  "px-3 py-1 text-xs font-medium transition-colors",
                  nj.mode === m
                    ? m === "enforce"
                      ? "bg-green-100 text-green-800"
                      : "bg-yellow-100 text-yellow-800"
                    : "bg-white text-gray-500 hover:bg-gray-50",
                )}
              >
                {t(`modes.${m}`)}
              </button>
            ))}
          </div>
          <button
            onClick={onSave}
            disabled={!isDirty || isPending}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
          >
            <Save size={14} /> {t("config.save")}
          </button>
        </div>
      </div>

      <div className="space-y-2">
        <h4 className="text-xs font-semibold text-gray-600 uppercase tracking-wider">
          {t("config.kernelProbes")}
        </h4>
        <ToggleSwitch
          checked={pr.ebpf.enabled}
          onChange={(v) => onChange({ probes: { ...pr, ebpf: { enabled: v } } })}
          label={t("config.ebpfProbe")}
        />
        <ToggleSwitch
          checked={pr.uprobe.enabled}
          onChange={(v) => onChange({ probes: { ...pr, uprobe: { enabled: v } } })}
          label={t("config.uprobeProbe")}
        />
        <div className="flex items-center gap-3">
          <ToggleSwitch
            checked={pr.lsm.enabled}
            onChange={(v) =>
              onChange({ probes: { ...pr, lsm: { ...pr.lsm, enabled: v } } })
            }
            label={t("config.lsmProbe")}
          />
          {pr.lsm.enabled && (
            <select
              value={pr.lsm.minSeverity}
              onChange={(e) =>
                onChange({
                  probes: {
                    ...pr,
                    lsm: { ...pr.lsm, minSeverity: e.target.value as "high" | "critical" },
                  },
                })
              }
              className="text-sm border border-gray-300 rounded px-2 py-1"
            >
              <option value="high">high</option>
              <option value="critical">critical</option>
            </select>
          )}
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <ArrayEditor
          label={t("config.sensitivePaths")}
          help={t("config.sensitivePathsHelp")}
          placeholder="/etc/shadow"
          values={nj.sensitivePaths}
          onChange={(v) => onChange({ nativeJudge: { ...nj, sensitivePaths: v } })}
        />
        <ArrayEditor
          label={t("config.scratchDirs")}
          help={t("config.scratchDirsHelp")}
          placeholder="/tmp"
          values={nj.scratchDirs}
          onChange={(v) => onChange({ nativeJudge: { ...nj, scratchDirs: v } })}
        />
      </div>
    </div>
  );
}
