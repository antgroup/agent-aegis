import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
} from "recharts";
import { useTranslation } from "react-i18next";
import type { SecurityEvent } from "@claw-aegis-web/shared";

interface Props {
  events: SecurityEvent[];
}

const BLOCKED_COLORS = [
  "#ef4444", "#f97316", "#dc2626", "#ea580c", "#b91c1c",
  "#c2410c", "#991b1b", "#9a3412", "#7f1d1d", "#7c2d12",
  "#f43f5e", "#e11d48", "#be123c", "#9f1239",
];

const OBSERVED_COLORS = [
  "#eab308", "#f59e0b", "#3b82f6", "#6366f1", "#8b5cf6",
  "#0ea5e9", "#14b8a6", "#10b981", "#22c55e", "#84cc16",
  "#a855f7", "#d946ef", "#ec4899", "#06b6d4",
];

function groupByDefense(events: SecurityEvent[], result: string) {
  const map: Record<string, number> = {};
  for (const ev of events) {
    if (ev.result !== result) continue;
    map[ev.defense] = (map[ev.defense] ?? 0) + 1;
  }
  return Object.entries(map).map(([name, value]) => ({ name, value }));
}

export function EventBreakdownChart({ events }: Props) {
  const { t } = useTranslation();

  const blocked = groupByDefense(events, "blocked");
  const observed = groupByDefense(events, "observed");
  const hasData = blocked.length > 0 || observed.length > 0;

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4">
      <h3 className="text-sm font-semibold text-gray-900 mb-3">
        {t("dashboard.eventBreakdown")}
      </h3>
      {!hasData ? (
        <div className="flex items-center justify-center h-[220px] text-sm text-gray-400">
          {t("dashboard.noChartData")}
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            {observed.length > 0 && (
              <Pie
                data={observed}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={20}
                outerRadius={50}
              >
                {observed.map((_, i) => (
                  <Cell key={i} fill={OBSERVED_COLORS[i % OBSERVED_COLORS.length]} />
                ))}
              </Pie>
            )}
            {blocked.length > 0 && (
              <Pie
                data={blocked}
                dataKey="value"
                nameKey="name"
                cx="50%"
                cy="50%"
                innerRadius={58}
                outerRadius={85}
              >
                {blocked.map((_, i) => (
                  <Cell key={i} fill={BLOCKED_COLORS[i % BLOCKED_COLORS.length]} />
                ))}
              </Pie>
            )}
            <Tooltip />
            <Legend wrapperStyle={{ fontSize: 11 }} />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
