#!/usr/bin/env bash
# AgentAegis Hermes adapter installer.
#
# Usage:
#   cd /path/to/AgentAegis && bash adapters/hermes/install.sh
#
# What it does:
#   1. Compiles TypeScript (npm run build)
#   2. Copies necessary files to ~/.hermes/plugins/agent-aegis/
#   3. Creates default config.yaml if missing
#   4. Creates .agentaegis-root marker pointing to source
#   5. Checks Hermes configuration for potential conflicts
#
# Note: Hermes has no built-in plugin install command.
# Plugins are loaded automatically from ~/.hermes/plugins/ directory.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"
HERMES_PLUGIN_DIR="${HOME}/.hermes/plugins/agent-aegis"
HERMES_CONFIG="${HOME}/.hermes/config.yaml"
HERMES_STATE_DIR="${HOME}/.hermes/agent-aegis-state"

echo "==> AgentAegis Hermes Adapter Installer"
echo "    Repo root:   $REPO_ROOT"
echo "    Plugin dir:  $HERMES_PLUGIN_DIR"
echo ""

# Check prerequisites
echo "==> Checking prerequisites..."

if ! command -v node &> /dev/null; then
    echo "    ERROR: Node.js not found. Please install Node.js >= 20."
    exit 1
fi

NODE_VERSION=$(node --version | cut -d'v' -f2 | cut -d'.' -f1)
if [ "$NODE_VERSION" -lt 20 ]; then
    echo "    WARNING: Node.js version is < 20. AgentAegis may not work correctly."
fi

echo "    Node.js: $(node --version)"

# Check if Hermes is installed
if ! command -v hermes &> /dev/null; then
    echo "    WARNING: Hermes command not found in PATH."
    echo "    Make sure Hermes is installed before using this plugin."
else
    echo "    Hermes: $(hermes --version 2>/dev/null || echo 'installed')"
fi

echo ""

# 1. Build TypeScript
echo "==> Building TypeScript..."
cd "$REPO_ROOT"
if [ ! -d node_modules ]; then
    echo "    Installing dependencies..."
    npm install
fi

if ! npx tsc --project tsconfig.json; then
    echo "    ERROR: TypeScript compilation failed."
    exit 1
fi

# Verify rpc-server.js exists
if [ ! -f "$REPO_ROOT/rpc-server.js" ]; then
    echo "    ERROR: rpc-server.js not found after build."
    exit 1
fi

echo "    Build successful."
echo ""

# 2. Build Web API
echo "==> Building Web API..."
cd "$REPO_ROOT/web/api"
if [ ! -d node_modules ]; then
    echo "    Installing web dependencies..."
    npm install
fi
if ! npm run build; then
    echo "    WARNING: Web API build failed. Web UI will not be available."
else
    echo "    Web API build successful."
fi
cd "$REPO_ROOT"
echo ""

# 3. Create plugin directory
echo "==> Installing plugin to Hermes..."
# Backups go OUTSIDE ~/.hermes/plugins/. Hermes discovers EVERY directory under
# plugins/ as a plugin, so a backup left in there (e.g. agent-aegis.backup.<ts>)
# loads as a duplicate, stale plugin and can shadow the fresh install.
BACKUP_ROOT="${HOME}/.hermes/agent-aegis-backups"

# Self-heal: relocate any legacy backups a previous installer left inside plugins/.
for _legacy in "${HERMES_PLUGIN_DIR}".backup.*; do
    [ -e "$_legacy" ] || continue
    mkdir -p "$BACKUP_ROOT"
    echo "    Relocating stale in-plugins backup out of plugins/: $_legacy"
    mv "$_legacy" "${BACKUP_ROOT}/$(basename "$_legacy")"
done

# Backup an existing real installation (to BACKUP_ROOT, not inside plugins/).
if [ -d "$HERMES_PLUGIN_DIR" ] && [ ! -L "$HERMES_PLUGIN_DIR" ]; then
    mkdir -p "$BACKUP_ROOT"
    BACKUP_DIR="${BACKUP_ROOT}/agent-aegis.$(date +%Y%m%d%H%M%S)"
    echo "    Backing up existing install to: $BACKUP_DIR"
    mv "$HERMES_PLUGIN_DIR" "$BACKUP_DIR"
fi

# Remove if it's a symlink
if [ -L "$HERMES_PLUGIN_DIR" ]; then
    rm "$HERMES_PLUGIN_DIR"
fi

# Create fresh plugin directory
mkdir -p "$HERMES_PLUGIN_DIR"

# Copy Python adapter files
echo "    Copying Python adapter files..."
cp "$SCRIPT_DIR/__init__.py" "$HERMES_PLUGIN_DIR/"
cp "$SCRIPT_DIR/plugin.yaml" "$HERMES_PLUGIN_DIR/"
cp "$SCRIPT_DIR/bridge.py" "$HERMES_PLUGIN_DIR/"
cp "$SCRIPT_DIR/tool_wrappers.py" "$HERMES_PLUGIN_DIR/"
cp "$SCRIPT_DIR/paths.py" "$HERMES_PLUGIN_DIR/"
cp "$SCRIPT_DIR/web-server.py" "$HERMES_PLUGIN_DIR/"

# Copy compiled RPC server
echo "    Copying RPC server..."
cp "$REPO_ROOT/rpc-server.js" "$HERMES_PLUGIN_DIR/"
cp "$REPO_ROOT/rpc-handlers.js" "$HERMES_PLUGIN_DIR/"

# Copy necessary src/ files (for imports)
echo "    Copying runtime dependencies..."
mkdir -p "$HERMES_PLUGIN_DIR/src"
cp "$REPO_ROOT/src/"*.js "$HERMES_PLUGIN_DIR/src/"

# Copy Web API
echo "    Copying Web API..."
mkdir -p "$HERMES_PLUGIN_DIR/web"
cp -r "$REPO_ROOT/web/api/dist/"* "$HERMES_PLUGIN_DIR/web/"
cp "$REPO_ROOT/web/api/package.json" "$HERMES_PLUGIN_DIR/web/"

# Copy frontend dist to static/ for served UI
if [ -d "$REPO_ROOT/web/frontend/dist" ]; then
    echo "    Copying frontend distribution..."
    mkdir -p "$HERMES_PLUGIN_DIR/web/static"
    cp -r "$REPO_ROOT/web/frontend/dist/"* "$HERMES_PLUGIN_DIR/web/static/"
else
    echo "    WARNING: Frontend dist not found. Web UI will be restricted to API only."
fi

# Create source root marker
echo "$REPO_ROOT" > "$HERMES_PLUGIN_DIR/.agentaegis-root"

echo "    Installed to: $HERMES_PLUGIN_DIR"
echo ""

# 4. Default config
CONFIG_FILE="$HERMES_PLUGIN_DIR/config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
    echo "==> Creating default config.yaml..."
    cat > "$CONFIG_FILE" << 'YAML'
# AgentAegis configuration for Hermes Agent.
# All defenses are enabled by default in enforce mode.
# Set a defense to false or its mode to "observe"/"off" to adjust.

allDefensesEnabled: true
defaultBlockingMode: enforce

# --- Web UI Configuration ---
# Set webPort to a number (e.g., 3800) to enable the Web UI
# Set to 0 or remove to disable
webPort: 3800

# --- Individual defense toggles ---
# selfProtectionEnabled: true
# selfProtectionMode: enforce
# commandBlockEnabled: true
# commandBlockMode: enforce
# encodingGuardEnabled: true
# encodingGuardMode: enforce
# scriptProvenanceGuardEnabled: true
# memoryGuardEnabled: true
# userRiskScanEnabled: true
# skillScanEnabled: true
# toolResultScanEnabled: true
# outputRedactionEnabled: true
# promptGuardEnabled: true
# loopGuardEnabled: true
# exfiltrationGuardMode: enforce
# toolCallEnforcementEnabled: true
# dispatchGuardEnabled: true

# --- Protected paths (additional) ---
# protectedPaths:
#   - /path/to/sensitive/dir

# --- Protected skills ---
# protectedSkills:
#   - important-skill

# --- Protected plugins ---
# protectedPlugins:
#   - audit-guard
YAML
    echo "    Created: $CONFIG_FILE"
else
    echo "    Config already exists, skipping."
fi
echo ""

# 5. State directory
mkdir -p "$HERMES_STATE_DIR"
echo "    State dir: $HERMES_STATE_DIR"
echo ""

# 6. Check Hermes configuration
echo "==> Checking Hermes configuration..."
if [ -f "$HERMES_CONFIG" ]; then
    if command -v yq &> /dev/null; then
        APPROVAL_MODE=$(yq e '.approvals.mode // "manual"' "$HERMES_CONFIG" 2>/dev/null || echo "manual")
        if [ "$APPROVAL_MODE" = "manual" ]; then
            echo "    WARNING: Hermes approvals.mode is 'manual'"
            echo "    You may see double prompts for dangerous commands."
            echo "    Consider setting 'approvals.mode: off' in $HERMES_CONFIG"
            echo "    to let AgentAegis handle all blocking."
        elif [ "$APPROVAL_MODE" = "smart" ]; then
            echo "    INFO: Hermes approvals.mode is 'smart'"
            echo "    Consider 'approvals.mode: off' for full AgentAegis control."
        else
            echo "    OK: Hermes approvals.mode is '$APPROVAL_MODE'"
        fi
    else
        echo "    INFO: Install 'yq' for automatic config checking"
        echo "    (https://github.com/mikefarah/yq)"
    fi
else
    echo "    INFO: Hermes config not found at $HERMES_CONFIG"
fi
echo ""

# 7. Summary
echo "==> Installation complete!"
echo ""
echo "    Next steps:"
echo "    1. Restart Hermes to activate AgentAegis"
echo "    2. Review config at: $CONFIG_FILE"
echo "    3. Set webPort in config to enable Web UI (e.g., webPort: 3800)"
echo ""
echo "    Important notes:"
echo "    - AgentAegis uses tool wrapping for blocking (Hermes pre_tool_call cannot block)"
echo "    - Consider 'approvals.mode: off' in Hermes config to avoid double prompts"
echo "    - Logs are stored in: $HERMES_STATE_DIR"
echo "    - To uninstall, remove $HERMES_PLUGIN_DIR"
echo ""
echo "    Web UI (when enabled):"
echo "    - Set webPort: 3800 in $CONFIG_FILE"
echo "    - Access at http://localhost:3800"
echo "    - Or run standalone: $REPO_ROOT/start-web-hermes.sh"
echo ""
