import { API_PREFIX } from "@claw-aegis-web/shared";
import type { ApiResponse } from "@claw-aegis-web/shared";

const BASE = API_PREFIX;

const TOKEN_STORAGE_KEY = "aegis-token";

// The token is never embedded in the page. The operator enters it once (it is
// shown in the server console / .aegis-webui-token, or set via AEGIS_TOKEN) and
// it is persisted in localStorage. In dev the Vite proxy injects the header, so
// no entry is needed there.
function storedToken(): string | undefined {
  try {
    return localStorage.getItem(TOKEN_STORAGE_KEY) ?? undefined;
  } catch {
    return undefined;
  }
}

// Single-flight prompt so concurrent 401s (multiple queries on first load) only
// open one dialog.
let tokenPrompt: Promise<string | undefined> | null = null;
function promptForToken(): Promise<string | undefined> {
  if (typeof window === "undefined") return Promise.resolve(undefined);
  if (!tokenPrompt) {
    tokenPrompt = Promise.resolve()
      .then(() => {
        const entered = window
          .prompt("Enter the Agent Aegis WebUI token (shown in the server console / .aegis-webui-token):")
          ?.trim();
        if (entered) {
          try {
            localStorage.setItem(TOKEN_STORAGE_KEY, entered);
          } catch {
            /* storage unavailable; will re-prompt next time */
          }
          return entered;
        }
        return undefined;
      })
      .finally(() => {
        tokenPrompt = null;
      });
  }
  return tokenPrompt;
}

async function request<T>(path: string, init?: RequestInit, retried = false): Promise<T> {
  const token = storedToken();
  const res = await fetch(`${BASE}${path}`, {
    headers: {
      "Content-Type": "application/json",
      ...(token ? { "x-aegis-token": token } : {}),
      ...init?.headers,
    },
    ...init,
  });

  if (res.status === 401) {
    if (!retried) {
      const entered = await promptForToken();
      if (entered) return request<T>(path, init, true);
    } else {
      // The entered token was rejected; clear it so the next action re-prompts.
      try {
        localStorage.removeItem(TOKEN_STORAGE_KEY);
      } catch {
        /* ignore */
      }
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
