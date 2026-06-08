import { clsx } from "clsx";
import type { DefenseMode } from "@agent-aegis-web/shared";
import { useTranslation } from "react-i18next";

const modeDefs: { value: DefenseMode; labelKey: string; color: string }[] = [
  { value: "off", labelKey: "modes.off", color: "bg-gray-200 text-gray-700" },
  { value: "observe", labelKey: "modes.observe", color: "bg-yellow-100 text-yellow-800" },
  { value: "enforce", labelKey: "modes.enforce", color: "bg-green-100 text-green-800" },
];

export function ModeSelector({
  value,
  onChange,
  disabled,
}: {
  value: DefenseMode;
  onChange: (mode: DefenseMode) => void;
  disabled?: boolean;
}) {
  const { t } = useTranslation();

  return (
    <div className="inline-flex rounded-md border border-gray-300 overflow-hidden">
      {modeDefs.map((m) => (
        <button
          key={m.value}
          type="button"
          disabled={disabled}
          onClick={() => onChange(m.value)}
          className={clsx(
            "px-3 py-1 text-xs font-medium transition-colors",
            value === m.value ? m.color : "bg-white text-gray-500 hover:bg-gray-50",
            disabled && "opacity-50 cursor-not-allowed",
          )}
        >
          {t(m.labelKey)}
        </button>
      ))}
    </div>
  );
}
