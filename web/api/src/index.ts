import path from "node:path";
import { fileURLToPath } from "node:url";
import { createServer } from "./server.js";

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const pluginRoot = path.resolve(__dirname, "..", "..", "..");

const port = parseInt(process.env.AEGIS_PORT ?? "3800", 10);
// Bind to loopback by default so the management API is not exposed to the local
// network / internet. Override with AEGIS_HOST=0.0.0.0 (or --host=0.0.0.0) only
// when remote access is intended — and pair it with AEGIS_TOKEN.
const host = process.env.AEGIS_HOST ?? "127.0.0.1";
const configDir = process.env.AEGIS_CONFIG_DIR ?? pluginRoot;
const defaultStateDir = pluginRoot.includes(path.join(".openclaw", "extensions"))
  ? path.resolve(pluginRoot, "..", "..", "plugins", "claw-aegis")
  : "";
const stateDir = process.env.AEGIS_STATE_DIR ?? defaultStateDir;

for (const arg of process.argv.slice(2)) {
  const [key, value] = arg.split("=");
  if (key === "--port" && value) Object.assign(process.env, { AEGIS_PORT: value });
  if (key === "--host" && value) Object.assign(process.env, { AEGIS_HOST: value });
  if (key === "--config-dir" && value) Object.assign(process.env, { AEGIS_CONFIG_DIR: value });
  if (key === "--state-dir" && value) Object.assign(process.env, { AEGIS_STATE_DIR: value });
}

const finalPort = parseInt(process.env.AEGIS_PORT ?? String(port), 10);
const finalHost = process.env.AEGIS_HOST ?? host;
const finalConfigDir = process.env.AEGIS_CONFIG_DIR ?? configDir;
const finalStateDir = process.env.AEGIS_STATE_DIR ?? stateDir;

const app = createServer({ configDir: finalConfigDir, stateDir: finalStateDir });

app.listen(finalPort, finalHost, () => {
  console.log(`[claw-aegis-web] API server listening on http://${finalHost}:${finalPort}`);
  if (finalHost === "0.0.0.0") {
    console.warn(
      "[claw-aegis-web] WARNING: bound to 0.0.0.0 — the management API is reachable from the local network. " +
        "Set AEGIS_HOST=127.0.0.1 to restrict. On an exposed bind, provide AEGIS_TOKEN out-of-band " +
        "(the auto-generated token is served to the UI and would be fetchable by network clients).",
    );
  }
  if (finalStateDir) {
    console.log(`[claw-aegis-web] State dir: ${finalStateDir}`);
  }
  console.log(`[claw-aegis-web] Config dir: ${finalConfigDir}`);
});
