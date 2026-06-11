import { useStatus, useEvents, useConfig, useChartEvents } from "../api/hooks";
import { DefenseConfigCard } from "../components/dashboard/DefenseConfigCard";
import { WeeklyEventChart } from "../components/dashboard/WeeklyEventChart";
import { EventBreakdownChart } from "../components/dashboard/EventBreakdownChart";
import { SkillTrustChart } from "../components/dashboard/SkillTrustChart";
import { StatusBadge } from "../components/common/StatusBadge";
import { Shield } from "lucide-react";
import { useTranslation } from "react-i18next";

export function DashboardPage() {
  const { t } = useTranslation();
  const { data: status, isLoading: statusLoading } = useStatus();
  const { data: configData } = useConfig();
  const { data: recentEvents } = useEvents({ limit: "3" });
  const { data: chartData } = useChartEvents();

  if (statusLoading) {
    return <div className="text-gray-500">{t("dashboard.loading")}</div>;
  }

  const config = configData?.config;
  const chartEvents = chartData?.events ?? [];

  return (
    <div className="space-y-6">
      <div className="flex items-center gap-3">
        <Shield size={24} className="text-blue-600" />
        <h1 className="text-xl font-bold">{t("dashboard.title")}</h1>
        {status?.configMtime && (
          <span className="text-xs text-gray-400 ml-auto">
            {t("dashboard.configUpdated")} {new Date(status.configMtime).toLocaleString()}
          </span>
        )}
      </div>

      {/* Top row: config summary + recent events */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {status && (
          <DefenseConfigCard
            defenses={status.defenses}
            trustedSkillCount={status.trustedSkillCount}
            protectedPaths={config?.protectedPaths ?? []}
            protectedSkills={config?.protectedSkills ?? []}
            protectedPlugins={config?.protectedPlugins ?? []}
          />
        )}

        <div className="bg-white rounded-lg border border-gray-200 h-full">
          <div className="px-4 py-3 border-b border-gray-100">
            <h3 className="text-sm font-semibold text-gray-900">
              {t("dashboard.recentEvents")}
            </h3>
          </div>
          {recentEvents?.events.length ? (
            <div className="divide-y divide-gray-100">
              {recentEvents.events.map((ev) => (
                <div key={ev.id} className="px-4 py-2.5">
                  <div className="flex items-center justify-between">
                    <span className="text-sm text-gray-700">{ev.defense}</span>
                    <StatusBadge value={ev.result} />
                  </div>
                  <p className="text-xs text-gray-500 mt-0.5">
                    {ev.reason ?? t("dashboard.noDetails")} &middot;{" "}
                    {new Date(ev.timestamp).toLocaleTimeString()}
                  </p>
                </div>
              ))}
            </div>
          ) : (
            <div className="p-4 text-sm text-gray-400">
              {t("dashboard.noEvents")}
            </div>
          )}
        </div>
      </div>

      {/* Bottom row: 3 charts */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-6">
        <WeeklyEventChart events={chartEvents} />
        <EventBreakdownChart events={chartEvents} />
        <SkillTrustChart />
      </div>
    </div>
  );
}
