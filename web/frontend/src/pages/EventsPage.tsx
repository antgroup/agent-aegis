import { useState } from "react";
import { useEvents } from "../api/hooks";
import { StatusBadge } from "../components/common/StatusBadge";
import { ScrollText, ChevronDown, ChevronRight } from "lucide-react";
import { useTranslation } from "react-i18next";

function hasDetail(ev: { commandText?: string; toolParams?: Record<string, unknown>; userInput?: string; details?: Record<string, unknown> }): boolean {
  return Boolean(ev.commandText || ev.userInput || (ev.toolParams && Object.keys(ev.toolParams).length > 0) || (ev.details && Object.keys(ev.details).length > 0));
}

export function EventsPage() {
  const { t } = useTranslation();
  const [defense, setDefense] = useState("");
  const [result, setResult] = useState("");
  const [expanded, setExpanded] = useState<Set<string>>(new Set());

  const params: Record<string, string> = { limit: "50" };
  if (defense) params.defense = defense;
  if (result) params.result = result;

  const { data, isLoading } = useEvents(params);

  const toggle = (id: string) => {
    setExpanded((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  };

  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <ScrollText size={24} className="text-blue-600" />
        <h1 className="text-xl font-bold">{t("events.title")}</h1>
        <span className="text-xs text-gray-400 ml-auto">
          {t("events.totalEvents", { count: data?.total ?? 0 })}
        </span>
      </div>

      <div className="flex items-center gap-3 mb-4">
        <select
          value={defense}
          onChange={(e) => setDefense(e.target.value)}
          className="text-sm border border-gray-300 rounded px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500"
        >
          <option value="">{t("events.allDefenses")}</option>
          <option value="selfProtection">{t("events.selfProtection")}</option>
          <option value="commandBlock">{t("events.commandBlock")}</option>
          <option value="encodingGuard">{t("events.encodingGuard")}</option>
          <option value="memoryGuard">{t("events.memoryGuard")}</option>
          <option value="loopGuard">{t("events.loopGuard")}</option>
          <option value="exfiltrationGuard">{t("events.exfiltrationGuard")}</option>
          <option value="skillScan">{t("events.skillScan")}</option>
          <option value="prompt_guard">{t("events.promptGuard")}</option>
          <option value="dispatch_guard">{t("events.dispatchGuard")}</option>
          <option value="tool_result_scan">{t("events.toolResultScan")}</option>
          <option value="user_risk_scan">{t("events.userRiskScan")}</option>
          <option value="prompt_self_block">{t("events.promptSelfBlock")}</option>
          <option value="config">{t("events.configEvent")}</option>
        </select>
        <select
          value={result}
          onChange={(e) => setResult(e.target.value)}
          className="text-sm border border-gray-300 rounded px-2 py-1.5 focus:outline-none focus:ring-1 focus:ring-blue-500"
        >
          <option value="">{t("events.allResults")}</option>
          <option value="blocked">{t("events.blocked")}</option>
          <option value="observed">{t("events.observed")}</option>
          <option value="clear">{t("events.clear")}</option>
        </select>
      </div>

      <div className="bg-white rounded-lg border border-gray-200 overflow-x-auto">
        {isLoading ? (
          <div className="p-4 text-sm text-gray-400">{t("events.loading")}</div>
        ) : data?.events.length ? (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-100 bg-gray-50">
                <th className="w-8 px-2 py-2" />
                <th className="text-left px-4 py-2 font-medium text-gray-600">{t("events.colTime")}</th>
                <th className="text-left px-4 py-2 font-medium text-gray-600">{t("events.colDefense")}</th>
                <th className="text-left px-4 py-2 font-medium text-gray-600">{t("events.colResult")}</th>
                <th className="text-left px-4 py-2 font-medium text-gray-600">{t("events.colTool")}</th>
                <th className="text-left px-4 py-2 font-medium text-gray-600">{t("events.colReason")}</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-100">
              {data.events.map((ev) => {
                const expandable = hasDetail(ev);
                const isOpen = expanded.has(ev.id);
                return (
                  <>
                    <tr
                      key={ev.id}
                      className={`hover:bg-gray-50 ${expandable ? "cursor-pointer" : ""}`}
                      onClick={() => expandable && toggle(ev.id)}
                    >
                      <td className="px-2 py-2 text-gray-400">
                        {expandable ? (
                          isOpen ? <ChevronDown size={14} /> : <ChevronRight size={14} />
                        ) : null}
                      </td>
                      <td className="px-4 py-2 text-gray-500 whitespace-nowrap">
                        {new Date(ev.timestamp).toLocaleString()}
                      </td>
                      <td className="px-4 py-2 font-medium">{ev.defense}</td>
                      <td className="px-4 py-2">
                        <StatusBadge value={ev.result} />
                      </td>
                      <td className="px-4 py-2 text-gray-600">{ev.toolName ?? "-"}</td>
                      <td className="px-4 py-2 text-gray-500 truncate max-w-xs">
                        {ev.reason ?? "-"}
                      </td>
                    </tr>
                    {expandable && isOpen && (
                      <tr key={`${ev.id}-detail`} className="bg-gray-50">
                        <td />
                        <td colSpan={5} className="px-4 py-3">
                          <div className="space-y-2 text-xs">
                            {ev.details && Object.keys(ev.details).length > 0 && (
                              <div className="flex flex-wrap gap-2">
                                {!!ev.details.hook && (
                                  <span className="inline-flex items-center gap-1">
                                    <span className="font-medium text-gray-600">{t("events.labelHook")}:</span>
                                    <code className="bg-purple-50 text-purple-700 px-1.5 py-0.5 rounded">{String(ev.details.hook)}</code>
                                  </span>
                                )}
                                {!!ev.details.mode && (
                                  <span className="inline-flex items-center gap-1">
                                    <span className="font-medium text-gray-600">{t("events.labelMode")}:</span>
                                    <StatusBadge value={String(ev.details.mode)} />
                                  </span>
                                )}
                                {!!ev.details.model && (
                                  <span className="inline-flex items-center gap-1">
                                    <span className="font-medium text-gray-600">{t("events.labelModel")}:</span>
                                    <code className="bg-green-50 text-green-700 px-1.5 py-0.5 rounded">{String(ev.details.model)}</code>
                                  </span>
                                )}
                                {!!ev.details.provider && (
                                  <span className="inline-flex items-center gap-1">
                                    <span className="font-medium text-gray-600">{t("events.labelProvider")}:</span>
                                    <code className="bg-green-50 text-green-700 px-1.5 py-0.5 rounded">{String(ev.details.provider)}</code>
                                  </span>
                                )}
                                {Array.isArray(ev.details.flags) && ev.details.flags.length > 0 && (
                                  <span className="inline-flex items-center gap-1">
                                    <span className="font-medium text-gray-600">{t("events.labelFlags")}:</span>
                                    {(ev.details.flags as string[]).map((flag) => (
                                      <span key={flag} className="bg-orange-50 text-orange-700 px-1.5 py-0.5 rounded">{flag}</span>
                                    ))}
                                  </span>
                                )}
                              </div>
                            )}
                            {ev.commandText && (
                              <div>
                                <span className="font-medium text-gray-600">{t("events.labelCommand")}:</span>{" "}
                                <code className="bg-gray-100 px-1.5 py-0.5 rounded text-red-700 break-all">
                                  {ev.commandText}
                                </code>
                              </div>
                            )}
                            {ev.toolParams && Object.keys(ev.toolParams).length > 0 && (
                              <div>
                                <span className="font-medium text-gray-600">{t("events.labelParams")}:</span>
                                <pre className="mt-1 bg-gray-100 p-2 rounded text-gray-700 overflow-x-auto whitespace-pre-wrap break-all">
                                  {JSON.stringify(ev.toolParams, null, 2)}
                                </pre>
                              </div>
                            )}
                            {ev.userInput && (
                              <div>
                                <span className="font-medium text-gray-600">{t("events.labelUserInput")}:</span>
                                <pre className="mt-1 bg-blue-50 p-2 rounded text-gray-700 overflow-x-auto whitespace-pre-wrap break-all">
                                  {ev.userInput}
                                </pre>
                              </div>
                            )}
                          </div>
                        </td>
                      </tr>
                    )}
                  </>
                );
              })}
            </tbody>
          </table>
        ) : (
          <div className="p-4 text-sm text-gray-400">{t("events.noMatch")}</div>
        )}
      </div>
    </div>
  );
}
