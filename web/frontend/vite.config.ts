import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

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
      "/api": "http://localhost:3800",
    },
  },
});
