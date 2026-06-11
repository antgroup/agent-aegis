#!/usr/bin/env bash
#
# Install the per-agent sentinel sidecar (L2/L3 kernel defense) for ONE runtime.
#
#   bash adapters/install-sentinel.sh openclaw
#   bash adapters/install-sentinel.sh hermes
#
# Why a sidecar (not inside the L1 plugin): eBPF needs root, and OpenClaw's
# plugin scanner blocks child_process — so L2/L3 ships as a SEPARATE per-agent
# component with its own install dir, its own config, its own launcher, and its
# events flowing into THAT agent's state dir (so each agent's WebUI shows its
# own L1 + L2/L3, fully independent of the other runtime).
#
# Installs to:
#   openclaw -> ~/.openclaw/agent-aegis-sentinel/   (events -> ~/.openclaw/plugins/agent-aegis)
#   hermes   -> ~/.hermes/agent-aegis-sentinel/     (events -> ~/.hermes/agent-aegis-state)
set -euo pipefail

RUNTIME="${1:-}"
case "$RUNTIME" in
  openclaw) INSTALL="$HOME/.openclaw/agent-aegis-sentinel"; STATE="$HOME/.openclaw/plugins/agent-aegis" ;;
  hermes)   INSTALL="$HOME/.hermes/agent-aegis-sentinel";   STATE="$HOME/.hermes/agent-aegis-state" ;;
  *) echo "usage: bash adapters/install-sentinel.sh <openclaw|hermes>"; exit 2 ;;
esac

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

echo "==> Installing sentinel sidecar for $RUNTIME"
echo "    install dir : $INSTALL"
echo "    events dir  : $STATE  (must match this agent's WebUI AEGIS_STATE_DIR)"

# 1. Build the engine if the compiled sentinel .js are missing.
if [ ! -f "$REPO_ROOT/sentinel/index.js" ]; then
  echo "==> sentinel/index.js missing — building (npm run build)"
  [ -d node_modules ] || npm install --no-audit --no-fund
  npm run build
fi

# 2. Copy the sentinel subsystem into the per-agent install dir (OUTSIDE any
#    scanned plugin dir → child_process is fine here). Ship compiled .js + the
#    probe runners (probe.py, lsm Go source); drop .ts sources and unit tests.
echo "==> Copying sentinel subsystem"
rm -rf "$INSTALL/sentinel"
mkdir -p "$INSTALL/sentinel"
cp -R "$REPO_ROOT/sentinel/." "$INSTALL/sentinel/"
rm -rf "$INSTALL/sentinel/__tests__" 2>/dev/null || true
find "$INSTALL/sentinel" -type d -name '__tests__' -exec rm -rf {} + 2>/dev/null || true
find "$INSTALL/sentinel" -name '*.ts' -delete 2>/dev/null || true

# 3. Write this agent's dedicated sentinel config (independent of the L1 config).
CFG="$INSTALL/config.json"
if [ -f "$CFG" ]; then
  echo "==> Keeping existing config: $CFG (only refreshing stateDir)"
  node -e 'const fs=require("fs"),p=process.argv[1],s=process.argv[2];const c=JSON.parse(fs.readFileSync(p,"utf8"));c.stateDir=s;fs.writeFileSync(p,JSON.stringify(c,null,2)+"\n")' "$CFG" "$STATE"
else
  echo "==> Writing default config: $CFG"
  node -e 'const fs=require("fs"),src=process.argv[1],dst=process.argv[2],s=process.argv[3];const c=JSON.parse(fs.readFileSync(src,"utf8"));c.stateDir=s;fs.writeFileSync(dst,JSON.stringify(c,null,2)+"\n")' \
    "$REPO_ROOT/sentinel/sidecar/config.example.json" "$CFG" "$STATE"
fi
mkdir -p "$STATE"

# 4. Write the launcher (run as root; eBPF needs it).
LAUNCH="$INSTALL/start-sentinel.sh"
cat > "$LAUNCH" <<EOF
#!/usr/bin/env bash
# Per-agent sentinel sidecar launcher ($RUNTIME). Run as root.
#   sudo bash "$LAUNCH"
exec node "$INSTALL/sentinel/sidecar/run.mjs" --config "$INSTALL/config.json" "\$@"
EOF
chmod +x "$LAUNCH"

echo
echo "==> Done. Edit defenses in: $CFG"
echo "    (mode observe/enforce; probes.ebpf/uprobe/lsm.enabled; sensitivePaths)"
echo "    Launch (root):  sudo bash $LAUNCH"
echo "    Events flow to: $STATE/defense-events.jsonl  → this agent's WebUI Events page"
echo "    Prereqs: Linux + root + BCC (bpfcc-tools python3-bpfcc) + /sys/kernel/debug;"
echo "             LSM enforce additionally needs kernel >=5.7 + BTF + bpf in /sys/kernel/security/lsm."
