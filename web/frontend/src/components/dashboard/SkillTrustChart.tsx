import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
} from "recharts";
import { useTranslation } from "react-i18next";
import { useSkills, useSkillScans } from "../../api/hooks";

const COLORS = ["#22c55e", "#f59e0b"];

export function SkillTrustChart() {
  const { t } = useTranslation();
  const { data: skillsData } = useSkills();
  const { data: scansData } = useSkillScans();

  const trusted = skillsData?.trustedSkills?.length ?? 0;
  const risky = scansData?.events?.filter((e) => !e.trusted).length ?? 0;

  const chartData = [
    { name: t("dashboard.trusted"), value: trusted },
    { name: t("dashboard.untrusted"), value: risky },
  ];
  const hasData = trusted + risky > 0;

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4">
      <h3 className="text-sm font-semibold text-gray-900 mb-3">
        {t("dashboard.skillTrust")}
      </h3>
      {!hasData ? (
        <div className="flex items-center justify-center h-[220px] text-sm text-gray-400">
          {t("dashboard.noChartData")}
        </div>
      ) : (
        <ResponsiveContainer width="100%" height={220}>
          <PieChart>
            <Pie
              data={chartData.filter((d) => d.value > 0)}
              dataKey="value"
              nameKey="name"
              cx="50%"
              cy="50%"
              innerRadius={50}
              outerRadius={85}
              paddingAngle={2}
            >
              {chartData.filter((d) => d.value > 0).map((d) => (
                <Cell
                  key={d.name}
                  fill={d.name === t("dashboard.trusted") ? COLORS[0] : COLORS[1]}
                />
              ))}
            </Pie>
            <Tooltip />
            <Legend wrapperStyle={{ fontSize: 12 }} />
          </PieChart>
        </ResponsiveContainer>
      )}
    </div>
  );
}
