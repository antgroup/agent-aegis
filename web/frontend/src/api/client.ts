import { API_PREFIX } from "@claw-aegis-web/shared";
import type { ApiResponse } from "@claw-aegis-web/shared";

const BASE = API_PREFIX;

// The server injects the API token into the served HTML as <meta name="aegis-token">.
// It is required on write requests; we attach it to every request for simplicity.
// In dev, the Vite proxy injects the header instead, so the meta may be absent.
function authToken(): string | undefined {
  if (typeof document === "undefined") return undefined;
  return document.querySelector('meta[name="aegis-token"]')?.getAttribute("content") ?? undefined;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const token = authToken();
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "x-aegis-token": token } : {}),
      ...init?.headers,
    },
    ...init,
  });
  const json = (await res.json()) as ApiResponse<T>;
  if (!json.ok) throw new Error(json.error);
  return json.data;
}

export const api = {
  getConfig: () => request<{ config: import("@claw-aegis-web/shared").AegisConfig; defaults: import("@claw-aegis-web/shared").AegisConfig }>("/config"),
  updateConfig: (body: import("@claw-aegis-web/shared").ConfigUpdateRequest) =>
    request<{ config: import("@claw-aegis-web/shared").AegisConfig; defaults: import("@claw-aegis-web/shared").AegisConfig }>("/config", { method: "PUT", body: JSON.stringify(body) }),
  resetConfig: () =>
    request<{ config: import("@claw-aegis-web/shared").AegisConfig; defaults: import("@claw-aegis-web/shared").AegisConfig }>("/config/reset", { method: "POST" }),
  getStatus: () => request<import("@claw-aegis-web/shared").StatusResponse>("/status"),
  getEvents: (params?: Record<string, string>) => {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    return request<import("@claw-aegis-web/shared").EventsResponse>(`/events${qs}`);
  },
  getSkills: () => request<import("@claw-aegis-web/shared").SkillsResponse>("/skills"),
  removeSkill: (path: string) =>
    request<{ removed: boolean }>(`/skills/${encodeURIComponent(path)}`, { method: "DELETE" }),
  getSkillScans: (params?: Record<string, string>) => {
    const qs = params ? "?" + new URLSearchParams(params).toString() : "";
    return request<import("@claw-aegis-web/shared").SkillScanEventsResponse>(`/skill-scans${qs}`);
  },
};
