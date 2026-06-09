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
mkdir -p "$HERMES_PLUGIN_DIR"

# Backup existing installation if present
if [ -d "$HERMES_PLUGIN_DIR" ] && [ ! -L "$HERMES_PLUGIN_DIR" ]; then
    BACKUP_DIR="${HERMES_PLUGIN_DIR}.backup.$(date +%Y%m%d%H%M%S)"
    echo "    Backing up existing directory to: $BACKUP_DIR"
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

# Copy the sentinel subsystem (kernel-level eBPF/uprobe/LSM probes + native judge)
# so the RPC server can start it. Ship the compiled .js + the probe runners
# (probe.py, the LSM Go/C runner); drop the TS sources and unit tests.
echo "    Copying sentinel subsystem..."
mkdir -p "$HERMES_PLUGIN_DIR/sentinel"
cp -r "$REPO_ROOT/sentinel/"* "$HERMES_PLUGIN_DIR/sentinel/"
rm -rf "$HERMES_PLUGIN_DIR/sentinel/__tests__"
find "$HERMES_PLUGIN_DIR/sentinel" -name '*.ts' -delete 2>/dev/null || true

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

# --- Kernel-level defense (eBPF / sentinel) — opt-in, Linux only ---
# Requires root + BCC (bpfcc-tools, python3-bpfcc) + /sys/kernel/debug mounted.
# Same subsystem OpenClaw runs; probes fail-open (logged) if they cannot attach.
nativeJudge:
  # observe = detect + log + WebUI, never block; enforce = LSM blocks in-kernel.
  mode: observe
  # sensitivePaths:        # extra paths to flag (substring match)
  #   - /etc/shadow
  # scratchDirs:           # execve from these dirs => kernel-escape
  #   - /tmp/
probes:
  ebpf:
    enabled: false         # true => system-wide syscall observer (eBPF tracepoints)
  uprobe:
    enabled: false         # true => user-space libc/OpenSSL symbol probe
  lsm:
    enabled: false         # true (+ nativeJudge.mode: enforce) => in-kernel block
    minSeverity: high
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
