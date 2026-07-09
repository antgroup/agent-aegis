#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
IMAGE="${AEGIS_ADAPTER_DOCKER_IMAGE:-node:20-bookworm}"

if [ "${AEGIS_DOCKER_INNER:-0}" != "1" ]; then
  if ! command -v docker >/dev/null 2>&1; then
    echo "ERROR: docker is required on the host."
    exit 1
  fi

  echo "==> Running AgentAegis adapter verification inside Docker"
  echo "    Image: $IMAGE"
  echo "    Repo:  $REPO_ROOT"
  docker run --rm \
    -e AEGIS_DOCKER_INNER=1 \
    -e AEGIS_SKIP_NPM_INSTALL="${AEGIS_SKIP_NPM_INSTALL:-0}" \
    -v "$REPO_ROOT:/workspace" \
    -w /workspace \
    "$IMAGE" \
    bash adapters/verify-adapters-docker.sh
  exit $?
fi

export HOME="${AEGIS_DOCKER_HOME:-/tmp/agentaegis-home}"
export AGENT_AEGIS_STATE_DIR="${AEGIS_DOCKER_STATE_DIR:-/tmp/agentaegis-state}"
rm -rf "$HOME" "$AGENT_AEGIS_STATE_DIR"
mkdir -p "$HOME" "$AGENT_AEGIS_STATE_DIR"

echo "==> AgentAegis adapter verification"
echo "    node: $(node --version)"
echo "    npm:  $(npm --version)"
echo "    HOME: $HOME"
echo ""

if [ "${AEGIS_SKIP_NPM_INSTALL:-0}" != "1" ] && [ ! -d node_modules ]; then
  echo "==> Installing npm dependencies"
  npm install --no-audit --no-fund
  echo ""
fi

echo "==> Building AgentAegis runtime"
npm run build
echo ""

echo "==> Installing Codex hooks twice to verify idempotency"
bash adapters/codex/install.sh
bash adapters/codex/install.sh
echo ""

echo "==> Installing Claude Code hooks twice to verify idempotency"
bash adapters/claude-code/install.sh
bash adapters/claude-code/install.sh
echo ""

echo "==> Exercising installed hook commands"
node adapters/common/verify-installed-hooks.mjs

echo ""
echo "==> Docker adapter verification PASS"
