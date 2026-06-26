import { API_PREFIX } from "@claw-aegis-web/shared";
import type { ApiResponse } from "@claw-aegis-web/shared";

const BASE = API_PREFIX;

const TOKEN_STORAGE_KEY = "aegis-token";

// Default mode: the server injects the token into the served HTML as
// <meta name="aegis-token"> and we use it transparently. Hardened mode
// (AEGIS_TOKEN set): the token is NOT served, so we fall back to one the
// operator entered (persisted in localStorage), prompting once on a 401.
// In dev, the Vite proxy injects the header, so neither may be present.
function authToken(): string | undefined {
  if (typeof document !== "undefined") {
    const meta = document.querySelector('meta[name="aegis-token"]')?.getAttribute("content");
    if (meta) return meta;
  }
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

async function request<T>(path: string, init?: RequestInit, retried = false): Promise<T> {
  const token = authToken();
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "x-aegis-token": token } : {}),
      ...init?.headers,
    },
    ...init,
  });

  if (res.status === 401 && !retried && typeof window !== "undefined") {
    const entered = window.prompt(
      "This action requires the Agent Aegis API token.\n" +
        "Find it in the server console log or the .aegis-webui-token file (or your AEGIS_TOKEN value):",
    );
    if (entered?.trim()) {
      try {
        localStorage.setItem(TOKEN_STORAGE_KEY, entered.trim());
      } catch {
        /* storage unavailable; will re-prompt next time */
      }
      return request<T>(path, init, true);
    }
  }

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
