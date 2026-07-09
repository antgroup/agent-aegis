#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_DIR="${HOME}/.claude/agent-aegis"
STATE_DIR="${HOME}/.claude/agent-aegis-state"
SETTINGS_FILE="${HOME}/.claude/settings.json"

echo "==> Installing AgentAegis hooks for Claude Code"
echo "    Repo root:   $REPO_ROOT"
echo "    Install dir: $INSTALL_DIR"

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node is required."
  exit 1
fi

cd "$REPO_ROOT"
npm run build

mkdir -p "$INSTALL_DIR/adapters/common" "$INSTALL_DIR/src" "$STATE_DIR" "$(dirname "$SETTINGS_FILE")"
cp "$REPO_ROOT/package.json" "$INSTALL_DIR/package.json"
cp "$REPO_ROOT/rpc-handlers.js" "$INSTALL_DIR/rpc-handlers.js"
cp "$REPO_ROOT/adapters/common/hook-runner.mjs" "$INSTALL_DIR/adapters/common/hook-runner.mjs"
cp "$REPO_ROOT/src/"*.js "$INSTALL_DIR/src/"
cp "$REPO_ROOT/adapters/hermes/config.yaml" "$INSTALL_DIR/config.yaml"

node "$SCRIPT_DIR/../codex/merge-hooks.mjs" "$SETTINGS_FILE" "$SCRIPT_DIR/settings-hooks.template.json" "$INSTALL_DIR"

echo "==> Claude Code hook install complete"
echo "    Settings: $SETTINGS_FILE"
echo "    Config:   $INSTALL_DIR/config.yaml"
echo "    State:    $STATE_DIR"
echo ""
echo "Restart Claude Code for user-level settings changes to take effect."
