#!/usr/bin/env node
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import process from "node:process";

import { AegisRpcRuntime } from "../../rpc-handlers.js";

const INPUT_LIMIT = 2 * 1024 * 1024;
const TOOL_RESULT_LIMIT = 65536;

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const agent = args.agent ?? "generic";
  const input = await readJsonStdin();
  const eventName = String(input.hook_event_name ?? input.hookEventName ?? args.event ?? "");
  const runtime = await createRuntime(agent, input);

  let output = null;
  if (eventName === "UserPromptSubmit") {
    output = await handleUserPrompt(runtime, agent, input);
  } else if (eventName === "PreToolUse") {
    output = await handlePreToolUse(runtime, agent, input);
  } else if (eventName === "PermissionRequest") {
    output = await handlePermissionRequest(runtime, agent, input);
  } else if (eventName === "PostToolUse" || eventName === "PostToolUseFailure") {
    output = await handlePostToolUse(runtime, agent, eventName, input);
  } else if (eventName === "SessionStart") {
    output = await handleSessionStart(runtime, agent, input);
  } else if (eventName === "Stop" || eventName === "SubagentStop") {
    output = handleStop(runtime, agent, eventName, input);
  }

  if (output) {
    process.stdout.write(`${JSON.stringify(output)}\n`);
  }
  process.exit(0);
}

async function createRuntime(agent, input) {
  const pluginRoot = resolvePluginRoot();
  const agentHome = path.join(os.homedir(), agent === "claude" ? ".claude" : ".codex");
  const installRoot =
    process.env.AGENT_AEGIS_HOME ??
    process.env.PLUGIN_ROOT ??
    process.env.CLAUDE_PLUGIN_ROOT ??
    pluginRoot;
  const stateDir =
    process.env.AGENT_AEGIS_STATE_DIR ?? path.join(agentHome, "agent-aegis-state");
  const configPath =
    process.env.AGENT_AEGIS_CONFIG ??
    firstExisting([
      path.join(installRoot, "config.json"),
      path.join(installRoot, "config.yaml"),
      path.join(pluginRoot, "config.json"),
      path.join(pluginRoot, "config.yaml"),
    ]);
  const cwd = typeof input.cwd === "string" ? input.cwd : process.cwd();
  const config = configPath ? loadConfig(configPath) : {};
  if (config.startupSkillScan === undefined || config.startupSkillScan === null) {
    config.startupSkillScan = false;
  }
  const skillRoots = [
    path.join(agentHome, "skills"),
    path.join(cwd, ".codex", "skills"),
    path.join(cwd, ".claude", "skills"),
  ].filter((p) => fs.existsSync(p));
  const protectedRoots = unique([
    installRoot,
    pluginRoot,
    agentHome,
    path.join(agentHome, "settings.json"),
    path.join(agentHome, "hooks.json"),
    path.join(agentHome, "config.toml"),
    stateDir,
    ...splitPathList(process.env.AGENT_AEGIS_PROTECTED_ROOTS),
  ]);

  const runtime = new AegisRpcRuntime();
  await runtime.init({
    config,
    stateDir,
    pluginRootDir: pluginRoot,
    skillRoots,
    protectedRoots,
  });
  return runtime;
}

async function handleSessionStart(runtime, agent, input) {
  const sessionKey = sessionKeyOf(agent, input);
  const guard = await runtime.getPromptGuard({ sessionKey });
  if (!guard.context) return null;
  return contextOutput(agent, "SessionStart", guard.context);
}

async function handleUserPrompt(runtime, agent, input) {
  const sessionKey = sessionKeyOf(agent, input);
  const prompt = String(input.prompt ?? input.user_prompt ?? input.userMessage ?? "");
  if (prompt) {
    runtime.checkUserInput({ content: prompt, sessionKey });
    runtime.updateState({
      method: "note_user_input",
      sessionKey,
      data: { content: prompt.slice(0, 500) },
    });
  }
  const guard = await runtime.getPromptGuard({ sessionKey });
  if (!guard.context) return null;
  return contextOutput(agent, "UserPromptSubmit", guard.context);
}

async function handlePreToolUse(runtime, agent, input) {
  const sessionKey = sessionKeyOf(agent, input);
  const runId = runIdOf(input);
  const { tool, args } = normalizeToolInput(input);
  if (!tool) return null;

  const result = runtime.checkBeforeTool({
    tool,
    args,
    sessionKey,
    runId,
  });
  if (!result.block) return null;

  const reason = result.reason ?? "Blocked by AgentAegis policy.";
  return denyToolOutput(agent, "PreToolUse", reason);
}

async function handlePermissionRequest(runtime, agent, input) {
  if (agent !== "codex") return null;
  const sessionKey = sessionKeyOf(agent, input);
  const runId = runIdOf(input);
  const { tool, args } = normalizeToolInput(input);
  if (!tool) return null;

  const result = runtime.checkBeforeTool({ tool, args, sessionKey, runId });
  if (!result.block) return null;

  const reason = result.reason ?? "Blocked by AgentAegis policy.";
  return {
    hookSpecificOutput: {
      hookEventName: "PermissionRequest",
      decision: { behavior: "deny", message: reason },
    },
  };
}

async function handlePostToolUse(runtime, agent, eventName, input) {
  const sessionKey = sessionKeyOf(agent, input);
  const runId = runIdOf(input);
  const { tool, args } = normalizeToolInput(input);
  if (!tool) return null;

  const result = runtime.checkToolResult({
    tool,
    args,
    result: stringifyForScan(input.tool_response ?? input.tool_output ?? input.result),
    sessionKey,
    runId,
  });
  if (!result.suspicious && result.riskFlags.length === 0) return null;

  const reason = `AgentAegis flagged tool output: ${result.riskFlags.join(", ") || "suspicious content"}`;
  if (agent === "codex") {
    return {
      decision: "block",
      reason,
      hookSpecificOutput: {
        hookEventName: "PostToolUse",
        additionalContext: reason,
      },
    };
  }
  return {
    hookSpecificOutput: {
      hookEventName: eventName,
      additionalContext: reason,
    },
  };
}

function handleStop(runtime, agent, eventName, input) {
  runtime.updateState({
    method: "clear_session",
    sessionKey: sessionKeyOf(agent, input),
  });
  return null;
}

function contextOutput(agent, eventName, context) {
  if (agent === "codex") {
    return {
      hookSpecificOutput: {
        hookEventName: eventName,
        additionalContext: context,
      },
    };
  }
  return {
    hookSpecificOutput: {
      hookEventName: eventName,
      additionalContext: context,
    },
  };
}

function denyToolOutput(agent, eventName, reason) {
  return {
    hookSpecificOutput: {
      hookEventName: eventName,
      permissionDecision: "deny",
      permissionDecisionReason: reason,
    },
  };
}

function normalizeToolInput(input) {
  const rawTool = String(input.tool_name ?? input.toolName ?? input.tool ?? "");
  const toolInput = isRecord(input.tool_input)
    ? input.tool_input
    : isRecord(input.toolInput)
      ? input.toolInput
      : {};
  if (!rawTool) return { tool: "", args: {} };

  if (rawTool === "Bash" || rawTool === "Shell") {
    return { tool: "bash", args: { command: String(toolInput.command ?? "") } };
  }
  if (
    rawTool === "apply_patch" ||
    rawTool === "Edit" ||
    rawTool === "Write" ||
    rawTool === "MultiEdit" ||
    rawTool === "NotebookEdit"
  ) {
    const normalizedTool =
      rawTool === "apply_patch" ? "apply_patch" : rawTool === "Write" ? "write" : "edit";
    return {
      tool: normalizedTool,
      args: { ...toolInput, command: String(toolInput.command ?? toolInput.patch ?? "") },
    };
  }
  return { tool: rawTool, args: toolInput };
}

function sessionKeyOf(agent, input) {
  return String(
    input.session_id ??
      input.sessionId ??
      process.env.AGENT_AEGIS_SESSION_KEY ??
      `${agent}:default`,
  );
}

function runIdOf(input) {
  return String(input.turn_id ?? input.tool_use_id ?? input.runId ?? input.session_id ?? "unknown");
}

function stringifyForScan(value) {
  if (typeof value === "string") return value.slice(0, TOOL_RESULT_LIMIT);
  try {
    return JSON.stringify(value ?? null).slice(0, TOOL_RESULT_LIMIT);
  } catch {
    return String(value).slice(0, TOOL_RESULT_LIMIT);
  }
}

async function readJsonStdin() {
  const chunks = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    total += chunk.length;
    if (total > INPUT_LIMIT) throw new Error("hook input too large");
    chunks.push(Buffer.from(chunk));
  }
  const raw = Buffer.concat(chunks).toString("utf8").trim();
  if (!raw) return {};
  return JSON.parse(raw);
}

function parseArgs(argv) {
  const out = {};
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--agent") out.agent = argv[++i];
    else if (argv[i] === "--event") out.event = argv[++i];
  }
  return out;
}

function resolvePluginRoot() {
  let dir = path.dirname(new URL(import.meta.url).pathname);
  for (let i = 0; i < 6; i += 1) {
    if (fs.existsSync(path.join(dir, "rpc-handlers.js")) && fs.existsSync(path.join(dir, "src"))) {
      return dir;
    }
    dir = path.dirname(dir);
  }
  return process.cwd();
}

function loadConfig(filePath) {
  const raw = fs.readFileSync(filePath, "utf8");
  if (filePath.endsWith(".json")) return JSON.parse(raw);
  return parseSimpleYaml(raw);
}

function parseSimpleYaml(raw) {
  const out = {};
  for (const line of raw.split(/\r?\n/)) {
    const trimmed = line.trim();
    if (!trimmed || trimmed.startsWith("#") || !trimmed.includes(":")) continue;
    const idx = trimmed.indexOf(":");
    const key = trimmed.slice(0, idx).trim();
    const value = trimmed.slice(idx + 1).trim();
    if (!key || key.startsWith("-")) continue;
    out[key] = parseYamlScalar(value);
  }
  return out;
}

function parseYamlScalar(value) {
  if (value === "true") return true;
  if (value === "false") return false;
  if (value === "null" || value === "") return null;
  if (/^-?\d+(\.\d+)?$/.test(value)) return Number(value);
  if (value.startsWith("[") && value.endsWith("]")) {
    return value
      .slice(1, -1)
      .split(",")
      .map((item) => item.trim().replace(/^['"]|['"]$/g, ""))
      .filter(Boolean);
  }
  return value.replace(/^['"]|['"]$/g, "");
}

function firstExisting(paths) {
  return paths.find((p) => p && fs.existsSync(p));
}

function splitPathList(value) {
  return value ? value.split(path.delimiter).filter(Boolean) : [];
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function isRecord(value) {
  return !!value && typeof value === "object" && !Array.isArray(value);
}

main().catch((err) => {
  console.error(`[AgentAegis] hook failed open: ${err instanceof Error ? err.message : String(err)}`);
  process.exit(0);
});
