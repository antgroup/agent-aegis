import path from "node:path";
import os from "node:os";
import { fileURLToPath } from "node:url";
import { createServer } from "./server.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pluginRoot = path.resolve(__dirname, "..", "..", "..");

function expandHome(p: string): string {
  if (p.startsWith("~")) {
    return path.join(os.homedir(), p.slice(1));
  }
  return p;
}

const port = parseInt(process.env.AEGIS_PORT ?? "3800", 10);
// Bind to loopback by default so the management API is not exposed to the local
// network / internet. Override with AEGIS_HOST=0.0.0.0 (or --host=0.0.0.0) only
// when remote access is intended — and pair it with AEGIS_TOKEN.
const host = process.env.AEGIS_HOST ?? "127.0.0.1";
const configDir = expandHome(process.env.AEGIS_CONFIG_DIR ?? pluginRoot);
const defaultStateDir = pluginRoot.includes(path.join(".openclaw", "extensions"))
  ? path.resolve(pluginRoot, "..", "..", "plugins", "agent-aegis")
  : pluginRoot.includes(path.join(".hermes", "plugins"))
    ? path.resolve(pluginRoot, "..", "..", "agent-aegis-state")
    : "";
const stateDir = expandHome(process.env.AEGIS_STATE_DIR ?? defaultStateDir);
// L2/L3 sentinel sidecar config — a SEPARATE per-agent file. Default by runtime.
const defaultSentinelConfig =
  (process.env.AEGIS_APP ?? "openclaw") === "hermes"
    ? "~/.hermes/agent-aegis-sentinel/config.json"
    : "~/.openclaw/agent-aegis-sentinel/config.json";

for (const arg of process.argv.slice(2)) {
  const [key, value] = arg.split("=");
  if (key === "--port" && value) Object.assign(process.env, { AEGIS_PORT: value });
  if (key === "--host" && value) Object.assign(process.env, { AEGIS_HOST: value });
  if (key === "--config-dir" && value) Object.assign(process.env, { AEGIS_CONFIG_DIR: value });
  if (key === "--state-dir" && value) Object.assign(process.env, { AEGIS_STATE_DIR: value });
  if (key === "--sentinel-config" && value) Object.assign(process.env, { AEGIS_SENTINEL_CONFIG: value });
}

const finalPort = parseInt(process.env.AEGIS_PORT ?? String(port), 10);
const finalHost = process.env.AEGIS_HOST ?? host;
const finalConfigDir = process.env.AEGIS_CONFIG_DIR ?? configDir;
const finalStateDir = process.env.AEGIS_STATE_DIR ?? stateDir;
const finalSentinelConfigPath = expandHome(process.env.AEGIS_SENTINEL_CONFIG ?? defaultSentinelConfig);

const { app } = createServer({
    configDir: finalConfigDir,
    stateDir: finalStateDir,
    sentinelConfigPath: finalSentinelConfigPath
});

app.listen(finalPort, finalHost, () => {
  console.log(`[agent-aegis-web] API server listening on http://${finalHost}:${finalPort}`);
  console.log(`[agent-aegis-web] App: ${process.env.AEGIS_APP || "openclaw"}`);
  if (finalHost === "0.0.0.0" || finalHost === "::") {
    console.warn(
      `[agent-aegis-web] WARNING: bound to ${finalHost} — the management API is reachable from the local network. ` +
        "Set AEGIS_HOST=127.0.0.1 to restrict. On an exposed bind, provide AEGIS_TOKEN out-of-band " +
        "(the auto-generated token is printed to the console and would be reachable by network clients).",
    );
  }
  if (finalStateDir) {
    console.log(`[agent-aegis-web] State dir: ${finalStateDir}`);
  }
  console.log(`[agent-aegis-web] Config dir: ${finalConfigDir}`);
  console.log(`[agent-aegis-web] Sentinel config: ${finalSentinelConfigPath}`);
});
