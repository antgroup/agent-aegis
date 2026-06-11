import { API_PREFIX } from "@agent-aegis-web/shared";
import type { ApiResponse } from "@agent-aegis-web/shared";

const BASE = API_PREFIX;

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE}${path}`, {
    headers: { "Content-Type": "application/json", ...init?.headers },
    ...init,
  });
  const json = (await res.json()) as ApiResponse<T>;
  if (!json.ok) throw new Error(json.error);
  return json.data;
}

export const api = {
  getConfig: () => request<{ config: import("@agent-aegis-web/shared").AegisConfig; defaults: import("@agent-aegis-web/shared").AegisConfig }>("/config"),
  updateConfig: (body: import("@agent-aegis-web/shared").ConfigUpdateRequest) =>
    request<{ config: import("@agent-aegis-web/shared").AegisConfig; defaults: import("@agent-aegis-web/shared").AegisConfig }>("/config", { method: "PUT", body: JSON.stringify(body) }),
  resetConfig: () =>
    request<{ config: import("@agent-aegis-web/shared").AegisConfig; defaults: import("@agent-aegis-web/shared").AegisConfig }>("/config/reset", { method: "POST" }),
  getSentinelConfig: () =>
    request<{ config: import("@agent-aegis-web/shared").SentinelConfig; defaults: import("@agent-aegis-web/shared").SentinelConfig }>("/sentinel-config"),
  updateSentinelConfig: (body: import("@agent-aegis-web/shared").SentinelConfigUpdateRequest) =>
    request<{ config: import("@agent-aegis-web/shared").SentinelConfig; defaults: import("@agent-aegis-web/shared").SentinelConfig }>("/sentinel-config", { method: "PUT", body: JSON.stringify(body) }),
  resetSentinelConfig: () =>
    request<{ config: import("@agent-aegis-web/shared").SentinelConfig; defaults: import("@agent-aegis-web/shared").SentinelConfig }>("/sentinel-config/reset", { method: "POST" }),
  getStatus: () => request<import("@agent-aegis-web/shared").StatusResponse>("/status"),
  getEvents: (params?: Record<string, string>) => {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    return request<import("@agent-aegis-web/shared").EventsResponse>(`/events${qs}`);
  },
  getSkills: () => request<import("@agent-aegis-web/shared").SkillsResponse>("/skills"),
  removeSkill: (path: string) =>
    request<{ removed: boolean }>(`/skills/${encodeURIComponent(path)}`, { method: "DELETE" }),
  getSkillScans: (params?: Record<string, string>) => {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    return request<import("@agent-aegis-web/shared").SkillScanEventsResponse>(`/skill-scans${qs}`);
  },
};
