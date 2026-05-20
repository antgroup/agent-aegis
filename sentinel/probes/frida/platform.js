import path from "node:path";
import { fileURLToPath } from "node:url";
const HERE = path.dirname(fileURLToPath(import.meta.url));
/**
 * Decide whether Frida can run on the current platform and pick the right
 * agent script.
 *
 * Linux / macOS share the POSIX agent (libc / libSystem export the same
 * symbol names). Windows would need a separate agent — placeholder shipped
 * so that adding Windows hook code later is a one-file change.
 */
export function detectFridaSupport(platform = process.platform) {
    const posixTargets = ["execve", "openat", "connect"];
    switch (platform) {
        case "linux":
        case "darwin":
            return {
                supported: true,
                platform,
                agentScriptPath: path.join(HERE, "agent.js"),
                defaultTargets: posixTargets,
            };
        case "win32":
            return {
                supported: false,
                platform,
                agentScriptPath: path.join(HERE, "agent-win.js"),
                defaultTargets: [],
                reason: "Windows agent script is a placeholder; native hooks not implemented yet",
            };
        default:
            return {
                supported: false,
                platform,
                agentScriptPath: path.join(HERE, "agent.js"),
                defaultTargets: [],
                reason: `Frida probe has no agent script for platform=${platform}`,
            };
    }
}
