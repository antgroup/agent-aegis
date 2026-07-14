#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
PLUGIN_DIR="${HOME}/.codefuse/agent-aegis-plugin"
CONFIG_DIR="${HOME}/.codefuse/agent-aegis"
STATE_DIR="${HOME}/.codefuse/agent-aegis-state"
PLUGIN_ID="agent-aegis-codefuse@agent-aegis-local"

echo "==> Installing AgentAegis plugin for CodeFuse CC"
echo "    Repo root:  $REPO_ROOT"
echo "    Plugin dir: $PLUGIN_DIR"

if ! command -v node >/dev/null 2>&1; then
  echo "ERROR: node is required."
  exit 1
fi
if ! command -v cfuse >/dev/null 2>&1; then
  echo "ERROR: cfuse is required. Install CodeFuse CLI first."
  exit 1
fi

cd "$REPO_ROOT"
npm run build

mkdir -p \
  "$PLUGIN_DIR/.claude-plugin" \
  "$PLUGIN_DIR/hooks" \
  "$PLUGIN_DIR/adapters/common" \
  "$PLUGIN_DIR/src" \
  "$CONFIG_DIR" \
  "$STATE_DIR"
cp "$REPO_ROOT/package.json" "$PLUGIN_DIR/package.json"
cp "$REPO_ROOT/rpc-handlers.js" "$PLUGIN_DIR/rpc-handlers.js"
cp "$REPO_ROOT/adapters/common/hook-runner.mjs" "$PLUGIN_DIR/adapters/common/hook-runner.mjs"
cp "$REPO_ROOT/src/"*.js "$PLUGIN_DIR/src/"
cp "$SCRIPT_DIR/.claude-plugin/plugin.json" "$PLUGIN_DIR/.claude-plugin/plugin.json"
cp "$SCRIPT_DIR/.claude-plugin/marketplace.json" "$PLUGIN_DIR/.claude-plugin/marketplace.json"
cp "$SCRIPT_DIR/hooks/hooks.json" "$PLUGIN_DIR/hooks/hooks.json"
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
  cp "$SCRIPT_DIR/config.yaml" "$CONFIG_DIR/config.yaml"
fi

cfuse --skip-update --cc plugin validate "$PLUGIN_DIR"
cfuse --skip-update --cc plugin uninstall "$PLUGIN_ID" >/dev/null 2>&1 || true
cfuse --skip-update --cc plugin marketplace remove agent-aegis-local >/dev/null 2>&1 || true
cfuse --skip-update --cc plugin marketplace add "$PLUGIN_DIR"
cfuse --skip-update --cc plugin install "$PLUGIN_ID" --scope user

echo "==> CodeFuse CC plugin install complete"
echo "    Plugin: $PLUGIN_ID"
echo "    Config: $CONFIG_DIR/config.yaml"
echo "    State:  $STATE_DIR"
echo ""
echo "Start a new 'cfuse --cc' session for the plugin to take effect."
