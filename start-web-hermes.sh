#!/bin/bash
#
# Start AgentAegis Web UI for Hermes (standalone mode)
#
# This script starts the Hermes-compatible Web API server without requiring
# the full Hermes agent to be running. Useful for development and debugging.
#
# Usage:
#   ./start-web-hermes.sh [port]
#
# Environment variables:
#   AEGIS_PORT        - Web server port (default: 3800)
#   AEGIS_CONFIG_DIR  - Config directory (default: ~/.hermes/plugins/agent-aegis)
#   AEGIS_STATE_DIR   - State directory (default: ~/.hermes/agent-aegis-state)

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HERMES_HOME="${HERMES_HOME:-$HOME/.hermes}"

# Parse arguments
PORT="${1:-${AEGIS_PORT:-3800}}"

# Determine config directory
if [ -d "$HERMES_HOME/plugins/agent-aegis" ]; then
    # Installed mode - use plugin directory
    CONFIG_DIR="${AEGIS_CONFIG_DIR:-$HERMES_HOME/plugins/agent-aegis}"
    PLUGIN_DIR="$HERMES_HOME/plugins/agent-aegis"
else
    # Development mode - use repo directory
    CONFIG_DIR="${AEGIS_CONFIG_DIR:-$SCRIPT_DIR/adapters/hermes}"
    PLUGIN_DIR="$SCRIPT_DIR"
fi

STATE_DIR="${AEGIS_STATE_DIR:-$HERMES_HOME/agent-aegis-state}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting AgentAegis Web UI for Hermes...${NC}"
echo ""

# Check if the web UI is built. Build the FULL workspace (shared -> api ->
# frontend), not just web/api: web/api/dist imports @agent-aegis-web/shared,
# whose web/shared/dist/index.js must exist at runtime. Building only web/api
# leaves shared unbuilt -> ERR_MODULE_NOT_FOUND for @agent-aegis-web/shared.
WEB_DIR="$SCRIPT_DIR/web"
WEB_API_DIR="$WEB_DIR/api"
if [ ! -f "$WEB_DIR/shared/dist/index.js" ] || [ ! -f "$WEB_API_DIR/dist/index.js" ]; then
    echo -e "${YELLOW}Web UI not built. Building the workspace (shared + api + frontend)...${NC}"
    cd "$WEB_DIR"
    npm install
    npm run build
    cd "$SCRIPT_DIR"
fi

# Check if rpc-server.js is built
if [ -f "$PLUGIN_DIR/rpc-server.js" ]; then
    # Installed mode - use plugin directory
    RPC_SERVER="$PLUGIN_DIR/rpc-server.js"
elif [ -f "$SCRIPT_DIR/rpc-server.js" ]; then
    # Development mode - use repo root
    RPC_SERVER="$SCRIPT_DIR/rpc-server.js"
else
    echo -e "${YELLOW}RPC server not built. Building now...${NC}"
    cd "$SCRIPT_DIR"
    npm install
    npx tsc --project tsconfig.json
    RPC_SERVER="$SCRIPT_DIR/rpc-server.js"
fi

# Create directories if they don't exist
mkdir -p "$CONFIG_DIR"
mkdir -p "$STATE_DIR"

# Create default config if it doesn't exist
if [ ! -f "$CONFIG_DIR/config.yaml" ]; then
    echo -e "${YELLOW}Creating default config at $CONFIG_DIR/config.yaml${NC}"
    cat > "$CONFIG_DIR/config.yaml" << 'EOF'
allDefensesEnabled: true
defaultBlockingMode: enforce
webPort: 3800
EOF
fi

# Export environment variables
export AEGIS_APP="hermes"          # tells the WebUI to read/write config.yaml (not openclaw.plugin.json)
export AEGIS_PORT="$PORT"
export AEGIS_CONFIG_DIR="$CONFIG_DIR"
export AEGIS_STATE_DIR="$STATE_DIR"
export AEGIS_RPC_SERVER_PATH="$RPC_SERVER"
# AEGIS_STATIC_DIR - 前端静态文件目录
# 不设置则使用默认值 (../../frontend/dist)

echo "Configuration:"
echo "  Port:        $PORT"
echo "  Config dir:  $CONFIG_DIR"
echo "  State dir:   $STATE_DIR"
echo "  RPC server:  $RPC_SERVER"
echo ""
echo -e "${GREEN}Starting server...${NC}"
echo "  API:    http://localhost:$PORT/api/v1"
echo "  Health: http://localhost:$PORT/api/v1/health"
echo ""
echo "Press Ctrl+C to stop"
echo ""

# Start the server
cd "$WEB_API_DIR"
exec node dist/index.js
