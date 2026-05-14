import { Shield, Eye, ShieldOff, FolderLock, Puzzle, PackageCheck, ShieldCheck } from "lucide-react";
import { useTranslation } from "react-i18next";
import type { DefenseStatusEntry } from "@claw-aegis-web/shared";

interface Props {
  defenses: DefenseStatusEntry[];
  trustedSkillCount: number;
  protectedPaths: string[];
  protectedSkills: string[];
  protectedPlugins: string[];
}

export function DefenseConfigCard({
  defenses,
  trustedSkillCount,
  protectedPaths,
  protectedSkills,
  protectedPlugins,
}: Props) {
  const { t } = useTranslation();

  const enforcing = defenses.filter(
    (d) => d.mode === "enforce" || (!d.mode && d.enabled),
  ).length;
  const observing = defenses.filter((d) => d.mode === "observe").length;
  const disabled = defenses.filter(
    (d) => !d.enabled || d.mode === "off",
  ).length;

  const stats = [
    { icon: Shield, label: t("stats.enforcing"), count: enforcing, color: "text-green-600", bg: "bg-green-50" },
    { icon: Eye, label: t("stats.observing"), count: observing, color: "text-yellow-600", bg: "bg-yellow-50" },
    { icon: ShieldOff, label: t("stats.disabled"), count: disabled, color: "text-gray-500", bg: "bg-gray-50" },
  ];

  const assets = [
    { icon: FolderLock, label: t("dashboard.protectedPathsCount"), count: protectedPaths?.length ?? 0 },
    { icon: Puzzle, label: t("dashboard.protectedSkillsCount"), count: protectedSkills?.length ?? 0 },
    { icon: PackageCheck, label: t("dashboard.protectedPluginsCount"), count: protectedPlugins?.length ?? 0 },
    { icon: ShieldCheck, label: t("dashboard.trustedSkills"), count: trustedSkillCount },
  ];

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-5 h-full">
      <h3 className="text-sm font-semibold text-gray-900 mb-4">
        {t("dashboard.defenseConfig")}
      </h3>

      <div className="grid grid-cols-3 gap-3 mb-5">
        {stats.map((s) => (
          <div key={s.label} className={`${s.bg} rounded-lg p-3 text-center`}>
            <s.icon size={18} className={`${s.color} mx-auto mb-1`} />
            <div className={`text-xl font-bold ${s.color}`}>{s.count}</div>
            <div className="text-xs text-gray-500">{s.label}</div>
          </div>
        ))}
      </div>

      <div className="space-y-2.5">
        {assets.map((a) => (
          <div key={a.label} className="flex items-center justify-between text-sm">
            <span className="flex items-center gap-2 text-gray-600">
              <a.icon size={15} className="text-gray-400" />
              {a.label}
            </span>
            <span className="font-semibold text-gray-900">{a.count}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
