import { useState } from "react";
import { useSkills, useRemoveSkill, useSkillScans } from "../api/hooks";
import { Shield, Trash2, CheckCircle, AlertTriangle } from "lucide-react";
import { useTranslation } from "react-i18next";

type Tab = "scans" | "trusted";
type TrustFilter = "all" | "true" | "false";

export function SkillsPage() {
  const { t } = useTranslation();
  const [tab, setTab] = useState<Tab>("scans");
  const [trustFilter, setTrustFilter] = useState<TrustFilter>("all");

  const scanParams: Record<string, string> = {};
  if (trustFilter !== "all") scanParams.trusted = trustFilter;

  const { data: scanData, isLoading: scanLoading } = useSkillScans(scanParams);
  const { data: skillData, isLoading: skillLoading } = useSkills();
  const removeMutation = useRemoveSkill();

  const handleRemove = (path: string) => {
    if (confirm(t("skills.confirmRemove", { path }))) {
      removeMutation.mutate(path);
    }
  };

  const tabClass = (active: boolean) =>
    `px-4 py-2 text-sm font-medium border-b-2 cursor-pointer transition-colors ${
      active
        ? "border-blue-600 text-blue-600"
        : "border-transparent text-gray-500 hover:text-gray-700"
    }`;

  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <Shield size={24} className="text-blue-600" />
        <h1 className="text-xl font-bold">{t("skills.title")}</h1>
      </div>

      {/* Tabs */}
      <div className="flex border-b border-gray-200 mb-4">
        <button className={tabClass(tab === "scans")} onClick={() => setTab("scans")}>
          {t("skills.tabScanResults")}
          {scanData && (
            <span className="ml-2 text-xs text-gray-400">({scanData.total})</span>
          )}
        </button>
        <button className={tabClass(tab === "trusted")} onClick={() => setTab("trusted")}>
          {t("skills.tabTrustedSkills")}
          {skillData && (
            <span className="ml-2 text-xs text-gray-400">({skillData.total})</span>
          )}
        </button>
      </div>

      {/* Scan Results Tab */}
      {tab === "scans" && (
        <div>
          {/* Trust filter */}
          <div className="flex gap-2 mb-4">
            {(["all", "true", "false"] as TrustFilter[]).map((f) => (
              <button
                key={f}
                onClick={() => setTrustFilter(f)}
                className={`px-3 py-1 text-xs rounded-full border ${
                  trustFilter === f
                    ? "bg-blue-50 border-blue-300 text-blue-700"
                    : "border-gray-200 text-gray-500 hover:border-gray-300"
                }`}
              >
                {f === "all"
                  ? t("skills.filterAll")
                  : f === "true"
                    ? t("skills.filterTrusted")
                    : t("skills.filterRisky")}
              </button>
            ))}
            <span className="text-xs text-gray-400 ml-auto self-center">
              {t("skills.totalScans", { count: scanData?.total ?? 0 })}
            </span>
          </div>

          <div className="bg-white rounded-lg border border-gray-200 overflow-x-auto">
            {scanLoading ? (
              <div className="p-4 text-sm text-gray-400">{t("skills.loading")}</div>
            ) : scanData?.events.length ? (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-100 bg-gray-50">
                    <th className="text-left px-4 py-2 font-medium text-gray-600">{t("skills.colTime")}</th>
                    <th className="text-left px-4 py-2 font-medium text-gray-600">{t("skills.colSkillId")}</th>
                    <th className="text-left px-4 py-2 font-medium text-gray-600">{t("skills.colPath")}</th>
                    <th className="text-left px-4 py-2 font-medium text-gray-600">{t("skills.colResult")}</th>
                    <th className="text-left px-4 py-2 font-medium text-gray-600">{t("skills.colFindings")}</th>
                    <th className="text-left px-4 py-2 font-medium text-gray-600">{t("skills.colPhase")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {scanData.events.map((ev) => (
                    <tr key={ev.id} className="hover:bg-gray-50">
                      <td className="px-4 py-2 text-gray-500 text-xs whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleString()}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs">{ev.skillId}</td>
                      <td className="px-4 py-2 font-mono text-xs truncate max-w-xs" title={ev.path}>
                        {ev.path}
                      </td>
                      <td className="px-4 py-2">
                        {ev.trusted ? (
                          <span className="inline-flex items-center gap-1 text-xs text-green-700 bg-green-50 px-2 py-0.5 rounded-full">
                            <CheckCircle size={12} />
                            {t("skills.trusted")}
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-1 text-xs text-amber-700 bg-amber-50 px-2 py-0.5 rounded-full">
                            <AlertTriangle size={12} />
                            {t("skills.risky")}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-xs text-gray-600">
                        {ev.findings.length > 0 ? (
                          <ul className="list-disc list-inside">
                            {ev.findings.map((f, i) => (
                              <li key={i} className="text-amber-600">{f}</li>
                            ))}
                          </ul>
                        ) : (
                          <span className="text-gray-400">{t("skills.noFindings")}</span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-xs text-gray-500">
                        {ev.phase === "startup"
                          ? t("skills.phaseStartup")
                          : ev.phase === "turn_review"
                            ? t("skills.phaseTurnReview")
                            : ev.phase}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="p-4 text-sm text-gray-400">{t("skills.noScans")}</div>
            )}
          </div>
        </div>
      )}

      {/* Trusted Skills Tab */}
      {tab === "trusted" && (
        <div>
          <div className="flex mb-4">
            <span className="text-xs text-gray-400 ml-auto">
              {t("skills.totalSkills", { count: skillData?.total ?? 0 })}
            </span>
          </div>
          <div className="bg-white rounded-lg border border-gray-200 overflow-x-auto">
            {skillLoading ? (
              <div className="p-4 text-sm text-gray-400">{t("skills.loading")}</div>
            ) : skillData?.trustedSkills.length ? (
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-gray-100 bg-gray-50">
                    <th className="text-left px-4 py-2 font-medium text-gray-600">{t("skills.colPath")}</th>
                    <th className="text-left px-4 py-2 font-medium text-gray-600">{t("skills.colHash")}</th>
                    <th className="text-left px-4 py-2 font-medium text-gray-600">{t("skills.colSize")}</th>
                    <th className="text-left px-4 py-2 font-medium text-gray-600">{t("skills.colScanned")}</th>
                    <th className="text-right px-4 py-2 font-medium text-gray-600">{t("skills.colActions")}</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-100">
                  {skillData.trustedSkills.map((skill) => (
                    <tr key={skill.path} className="hover:bg-gray-50">
                      <td className="px-4 py-2 font-mono text-xs truncate max-w-xs">
                        {skill.path}
                      </td>
                      <td className="px-4 py-2 font-mono text-xs text-gray-500">
                        {skill.hash.slice(0, 12)}...
                      </td>
                      <td className="px-4 py-2 text-gray-600">
                        {(skill.size / 1024).toFixed(1)} KB
                      </td>
                      <td className="px-4 py-2 text-gray-500">
                        {new Date(skill.scannedAt).toLocaleString()}
                      </td>
                      <td className="px-4 py-2 text-right">
                        <button
                          onClick={() => handleRemove(skill.path)}
                          disabled={removeMutation.isPending}
                          className="text-red-500 hover:text-red-700 disabled:opacity-50"
                          title={t("skills.removeTitle")}
                        >
                          <Trash2 size={14} />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            ) : (
              <div className="p-4 text-sm text-gray-400">
                {t("skills.noSkills")}
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}
