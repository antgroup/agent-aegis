import { useState, useEffect, useCallback } from "react";
import { DEFENSE_GROUPS } from "@claw-aegis-web/shared";
import type { AegisConfig } from "@claw-aegis-web/shared";
import { useConfig, useUpdateConfig, useResetConfig } from "../api/hooks";
import { MasterControls } from "../components/config/MasterControls";
import { DefenseGroup } from "../components/config/DefenseGroup";
import { ArrayEditor } from "../components/config/ArrayEditor";
import { ToggleSwitch } from "../components/common/ToggleSwitch";
import { Save, RotateCcw, ChevronDown, ChevronRight } from "lucide-react";
import { useTranslation } from "react-i18next";

export function ConfigPage() {
  const { t } = useTranslation();
  const { data, isLoading, error } = useConfig();
  const updateMutation = useUpdateConfig();
  const resetMutation = useResetConfig();

  const [draft, setDraft] = useState<AegisConfig | null>(null);
  const [showAdvanced, setShowAdvanced] = useState(false);

  useEffect(() => {
    if (data?.config && !draft) {
      setDraft({ ...data.config });
    }
  }, [data, draft]);

  const patch = useCallback(
    (partial: Partial<AegisConfig>) => {
      setDraft((prev) => (prev ? { ...prev, ...partial } : prev));
    },
    [],
  );

  const isDirty =
    draft && data?.config && JSON.stringify(draft) !== JSON.stringify(data.config);

  const save = () => {
    if (!draft) return;
    updateMutation.mutate(draft, {
      onSuccess: (result) => setDraft({ ...result.config }),
    });
  };

  const reset = () => {
    resetMutation.mutate(undefined, {
      onSuccess: (result) => setDraft({ ...result.config }),
    });
  };

  if (isLoading) {
    return <div className="text-gray-500">{t("config.loading")}</div>;
  }
  if (error) {
    return <div className="text-red-600">{t("config.errorLoading")} {error.message}</div>;
  }
  if (!draft) return null;

  const defenseGroups = DEFENSE_GROUPS.filter(
    (g) => !["skillScan"].includes(g.id) || !g.id.includes("startup"),
  );
  const mainGroups = defenseGroups.slice(0, 7);
  const scanGroups = defenseGroups.slice(7);

  return (
    <div className="max-w-4xl">
      <div className="flex items-center justify-between mb-6">
        <h1 className="text-xl font-bold">{t("config.title")}</h1>
        <div className="flex items-center gap-3">
          {isDirty && (
            <span className="text-xs text-amber-600 font-medium">{t("config.unsavedChanges")}</span>
          )}
          <button
            onClick={reset}
            disabled={resetMutation.isPending}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm border border-gray-300 rounded-md hover:bg-gray-50 disabled:opacity-50"
          >
            <RotateCcw size={14} /> {t("config.resetDefaults")}
          </button>
          <button
            onClick={save}
            disabled={!isDirty || updateMutation.isPending}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 text-sm bg-blue-600 text-white rounded-md hover:bg-blue-700 disabled:opacity-50"
          >
            <Save size={14} /> {t("config.save")}
          </button>
        </div>
      </div>

      <MasterControls config={draft} onChange={patch} />

      <h2 className="text-sm font-semibold text-gray-600 uppercase tracking-wider mb-3">
        {t("config.executionGuards")}
      </h2>
      <div className="grid gap-3 mb-6">
        {mainGroups.map((g) => (
          <DefenseGroup key={g.id} group={g} config={draft} onChange={patch} />
        ))}
      </div>

      <h2 className="text-sm font-semibold text-gray-600 uppercase tracking-wider mb-3">
        {t("config.scanningOutput")}
      </h2>
      <div className="grid gap-3 mb-6">
        {scanGroups.map((g) => (
          <DefenseGroup key={g.id} group={g} config={draft} onChange={patch} />
        ))}
      </div>

      <h2 className="text-sm font-semibold text-gray-600 uppercase tracking-wider mb-3">
        {t("config.protectedAssets")}
      </h2>
      <div className="grid gap-3 mb-6">
        <ArrayEditor
          label={t("config.protectedPaths")}
          help={t("config.protectedPathsHelp")}
          placeholder={t("config.protectedPathsPlaceholder")}
          values={draft.protectedPaths}
          onChange={(v) => patch({ protectedPaths: v })}
        />
        <ArrayEditor
          label={t("config.protectedSkills")}
          help={t("config.protectedSkillsHelp")}
          placeholder={t("config.protectedSkillsPlaceholder")}
          values={draft.protectedSkills}
          onChange={(v) => patch({ protectedSkills: v })}
        />
        <ArrayEditor
          label={t("config.protectedPlugins")}
          help={t("config.protectedPluginsHelp")}
          placeholder={t("config.protectedPluginsPlaceholder")}
          values={draft.protectedPlugins}
          onChange={(v) => patch({ protectedPlugins: v })}
        />
      </div>

      <button
        type="button"
        onClick={() => setShowAdvanced(!showAdvanced)}
        className="flex items-center gap-1 text-sm text-gray-500 hover:text-gray-700 mb-3"
      >
        {showAdvanced ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
        {t("config.advancedSettings")}
      </button>
      {showAdvanced && (
        <div className="bg-white rounded-lg border border-gray-200 p-4 mb-6 space-y-4">
          <ToggleSwitch
            checked={draft.startupSkillScan}
            onChange={(v) => patch({ startupSkillScan: v })}
            label={t("config.startupSkillScan")}
          />
          <div className="border-t border-gray-100 pt-4">
            <ToggleSwitch
              checked={draft.webUiEnabled}
              onChange={(v) => patch({ webUiEnabled: v })}
              label={t("config.enableWebUi")}
            />
            {draft.webUiEnabled && (
              <div className="mt-3 flex items-center gap-3 ml-11">
                <span className="text-sm text-gray-600">{t("config.webUiPort")}:</span>
                <input
                  type="number"
                  value={draft.webUiPort}
                  onChange={(e) => patch({ webUiPort: parseInt(e.target.value, 10) || 3800 })}
                  className="w-20 text-sm border border-gray-300 rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-blue-500"
                />
              </div>
            )}
          </div>
        </div>
      )}

      {(updateMutation.isError || resetMutation.isError) && (
        <div className="mt-4 p-3 bg-red-50 text-red-700 text-sm rounded-md">
          {(updateMutation.error ?? resetMutation.error)?.message}
        </div>
      )}
    </div>
  );
}
