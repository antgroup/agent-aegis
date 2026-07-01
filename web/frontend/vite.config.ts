import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

// In dev the API requires a token on every request. Resolve it the same way
// the API server does (AEGIS_TOKEN, else the persisted .aegis-webui-token) and
// inject it into proxied /api requests so the dev UI works without manual setup.
function resolveDevToken(): string | undefined {
  const fromEnv = process.env.AEGIS_TOKEN?.trim();
  if (fromEnv) return fromEnv;
  const configDir = process.env.AEGIS_CONFIG_DIR?.replace(/^~/, os.homedir()) ?? path.resolve("..", "..");
  try {
    return fs.readFileSync(path.join(configDir, ".aegis-webui-token"), "utf8").trim() || undefined;
  } catch {
    return undefined;
  }
}

export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      output: {
        manualChunks: {
          vendor: ["react", "react-dom", "react-router-dom"],
          query: ["@tanstack/react-query"],
          charts: ["recharts"],
          i18n: ["i18next", "react-i18next"],
        },
      },
    },
  },
  server: {
    port: 3801,
    proxy: {
      "/api": {
        target: "http://localhost:3800",
        changeOrigin: false,
        configure: (proxy) => {
          const token = resolveDevToken();
          if (token) {
            proxy.on("proxyReq", (proxyReq) => proxyReq.setHeader("x-aegis-token", token));
          }
        },
      },
    },
  },
});
