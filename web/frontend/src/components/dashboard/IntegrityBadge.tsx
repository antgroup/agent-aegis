import type { SelfIntegrityStatus } from "@agent-aegis-web/shared";
import { ShieldCheck, ShieldAlert } from "lucide-react";
import { useTranslation } from "react-i18next";

export function IntegrityBadge({
  integrity,
}: {
  integrity: SelfIntegrityStatus;
}) {
  const { t } = useTranslation();

  if (!integrity) {
    return (
      <div className="bg-white rounded-lg border border-gray-200 p-4 flex items-center gap-3">
        <div className="p-2 bg-gray-50 rounded-lg text-gray-400">
          <ShieldAlert size={20} />
        </div>
        <div>
          <p className="text-sm font-medium text-gray-900">{t("integrity.title")}</p>
          <p className="text-xs text-gray-500">{t("integrity.noData")}</p>
        </div>
      </div>
    );
  }

  return (
    <div className="bg-white rounded-lg border border-gray-200 p-4 flex items-center gap-3">
      <div className="p-2 bg-green-50 rounded-lg text-green-600">
        <ShieldCheck size={20} />
      </div>
      <div>
        <p className="text-sm font-medium text-gray-900">{t("integrity.title")}</p>
        <p className="text-xs text-gray-500">
          {t("integrity.filesTracked", { count: integrity.fingerprintCount })} &middot;{" "}
          {t("integrity.protectedRoots", { count: integrity.protectedRoots.length })} &middot; {t("integrity.updated")}{" "}
          {new Date(integrity.updatedAt).toLocaleString()}
        </p>
      </div>
    </div>
  );
}
