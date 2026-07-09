#!/usr/bin/env node
import fs from "node:fs";
import path from "node:path";

const [targetPath, templatePath, installDir] = process.argv.slice(2);
if (!targetPath || !templatePath || !installDir) {
  console.error("usage: merge-hooks.mjs <target-json> <template-json> <install-dir>");
  process.exit(2);
}

const target = readJson(targetPath);
const templateRaw = fs.readFileSync(templatePath, "utf8").replaceAll("{{INSTALL_DIR}}", installDir);
const incoming = JSON.parse(templateRaw);

target.hooks = target.hooks && typeof target.hooks === "object" ? target.hooks : {};
for (const [eventName, groups] of Object.entries(incoming.hooks ?? {})) {
  const existing = Array.isArray(target.hooks[eventName]) ? target.hooks[eventName] : [];
  target.hooks[eventName] = mergeGroups(existing, groups);
}

if (fs.existsSync(targetPath)) {
  const backup = `${targetPath}.bak.${new Date().toISOString().replace(/[-:.TZ]/g, "")}`;
  fs.copyFileSync(targetPath, backup);
  console.error(`Backed up existing config to ${backup}`);
}
fs.mkdirSync(path.dirname(targetPath), { recursive: true });
fs.writeFileSync(targetPath, `${JSON.stringify(target, null, 2)}\n`);

function readJson(filePath) {
  if (!fs.existsSync(filePath)) return {};
  const raw = fs.readFileSync(filePath, "utf8").trim();
  return raw ? JSON.parse(raw) : {};
}

function mergeGroups(existing, incoming) {
  const out = [...existing];
  for (const group of incoming) {
    const key = groupKey(group);
    const index = out.findIndex((item) => groupKey(item) === key);
    if (index >= 0) out[index] = group;
    else out.push(group);
  }
  return out;
}

function groupKey(group) {
  const matcher = group.matcher ?? "";
  const hooks = Array.isArray(group.hooks) ? group.hooks : [];
  const commandKey = hooks
    .map((hook) => `${hook.command ?? ""} ${(hook.args ?? []).join(" ")}`)
    .join("|");
  return `${matcher}::${commandKey.includes("agent-aegis") ? "agent-aegis" : commandKey}`;
}
