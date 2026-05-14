import {
  ResponsiveContainer,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  Legend,
} from "recharts";
import { useTranslation } from "react-i18next";
import type { SecurityEvent } from "@claw-aegis-web/shared";

interface Props {
  events: SecurityEvent[];
}

function buildWeeklyData(events: SecurityEvent[]) {
  const now = new Date();
  const buckets: { date: string; blocked: number; observed: number }[] = [];

  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    const key = `${d.getMonth() + 1}/${d.getDate()}`;
    buckets.push({ date: key, blocked: 0, observed: 0 });
  }

  const startOfWeek = new Date(now);
  startOfWeek.setDate(startOfWeek.getDate() - 6);
  startOfWeek.setHours(0, 0, 0, 0);

  for (const ev of events) {
    if (ev.timestamp < startOfWeek.getTime()) continue;
    if (ev.result === "clear") continue;

    const evDate = new Date(ev.timestamp);
    const dayDiff = Math.floor(
      (evDate.getTime() - startOfWeek.getTime()) / (1000 * 60 * 60 * 24),
    );
    const idx = Math.min(Math.max(dayDiff, 0), 6);
    if (ev.result === "blocked") buckets[idx].blocked++;
    else if (ev.result === "observed") buckets[idx].observed++;
  }

  return buckets;
}

export function WeeklyEventChart({ events }: Props) {
  const { t } = useTranslation();
  const data = buildWeeklyData(events);

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4">
      <h3 className="text-sm font-semibold text-gray-900 mb-3">
        {t("dashboard.weeklyEvents")}
      </h3>
      {events.length === 0 ? (
        <div className="flex items-center justify-center h-[220px] text-sm text-gray-400">
          {t("dashboard.noChartData")}
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" stroke="#f0f0f0" />
            <XAxis dataKey="date" tick={{ fontSize: 12 }} />
            <YAxis allowDecimals={false} tick={{ fontSize: 12 }} width={30} />
            <Tooltip />
            <Legend wrapperStyle={{ fontSize: 12 }} />
            <Line
              type="monotone"
              dataKey="blocked"
              name={t("dashboard.blocked")}
              stroke="#ef4444"
              strokeWidth={2}
              dot={{ r: 3 }}
            />
            <Line
              type="monotone"
              dataKey="observed"
              name={t("dashboard.observed")}
              stroke="#eab308"
              strokeWidth={2}
              dot={{ r: 3 }}
            />
          </LineChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
