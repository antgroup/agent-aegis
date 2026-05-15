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
const configDir = expandHome(process.env.AEGIS_CONFIG_DIR ?? pluginRoot);
const defaultStateDir = pluginRoot.includes(path.join(".openclaw", "extensions"))
  ? path.resolve(pluginRoot, "..", "..", "plugins", "claw-aegis")
  : pluginRoot.includes(path.join(".hermes", "plugins"))
    ? path.resolve(pluginRoot, "..", "..", "claw-aegis-state")
    : "";
const stateDir = expandHome(process.env.AEGIS_STATE_DIR ?? defaultStateDir);

for (const arg of process.argv.slice(2)) {
  const [key, value] = arg.split("=");
  if (key === "--port" && value) Object.assign(process.env, { AEGIS_PORT: value });
  if (key === "--config-dir" && value) Object.assign(process.env, { AEGIS_CONFIG_DIR: value });
  if (key === "--state-dir" && value) Object.assign(process.env, { AEGIS_STATE_DIR: value });
}

const finalPort = parseInt(process.env.AEGIS_PORT ?? String(port), 10);
const finalConfigDir = process.env.AEGIS_CONFIG_DIR ?? configDir;
const finalStateDir = process.env.AEGIS_STATE_DIR ?? stateDir;

const { app } = createServer({ 
    configDir: finalConfigDir, 
    stateDir: finalStateDir
});

app.listen(finalPort, () => {
  console.log(`[claw-aegis-web] API server listening on http://localhost:${finalPort}`);
  console.log(`[claw-aegis-web] App: ${process.env.AEGIS_APP || "openclaw"}`);
  if (finalStateDir) {
    console.log(`[claw-aegis-web] State dir: ${finalStateDir}`);
  }
  console.log(`[claw-aegis-web] Config dir: ${finalConfigDir}`);
});
