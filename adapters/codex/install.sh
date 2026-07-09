#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
INSTALL_DIR="${HOME}/.codex/agent-aegis"
STATE_DIR="${HOME}/.codex/agent-aegis-state"
HOOKS_FILE="${HOME}/.codex/hooks.json"

echo "==> Installing AgentAegis hooks for Codex"
echo "    Repo root:   $REPO_ROOT"
echo "    Install dir: $INSTALL_DIR"

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node is required."
  exit 1
fi

cd "$REPO_ROOT"
npm run build

mkdir -p "$INSTALL_DIR/adapters/common" "$INSTALL_DIR/src" "$STATE_DIR" "$(dirname "$HOOKS_FILE")"
cp "$REPO_ROOT/package.json" "$INSTALL_DIR/package.json"
cp "$REPO_ROOT/rpc-handlers.js" "$INSTALL_DIR/rpc-handlers.js"
cp "$REPO_ROOT/adapters/common/hook-runner.mjs" "$INSTALL_DIR/adapters/common/hook-runner.mjs"
cp "$REPO_ROOT/src/"*.js "$INSTALL_DIR/src/"
cp "$REPO_ROOT/adapters/hermes/config.yaml" "$INSTALL_DIR/config.yaml"

node "$SCRIPT_DIR/merge-hooks.mjs" "$HOOKS_FILE" "$SCRIPT_DIR/hooks.template.json" "$INSTALL_DIR"

echo "==> Codex hook install complete"
echo "    Hooks:  $HOOKS_FILE"
echo "    Config: $INSTALL_DIR/config.yaml"
echo "    State:  $STATE_DIR"
echo ""
echo "Open /hooks in Codex and trust the AgentAegis hook definitions if prompted."
