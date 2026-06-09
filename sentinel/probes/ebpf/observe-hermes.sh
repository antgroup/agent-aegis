#!/usr/bin/env bash
#
# Live verification that the HERMES path starts eBPF observe, wired into the
# WebUI. Run via `npm run observe:hermes`.
#
# In a privileged Linux container it:
#   1. drives the real AegisRpcRuntime.init() (what `node rpc-server.js` runs
#      for Hermes) with probes.ebpf.enabled + nativeJudge.mode: observe, triggers
#      `cat /etc/shadow` (observed, NOT blocked), forwarding into
#      <state>/defense-events.jsonl;
#   2. serves the WebUI (web/api) on :3800 pointed at that state dir.
# The host then opens http://localhost:3800.
#
# Usage:
#   npm run observe:hermes                  # build web + image, run, open browser
#   npm run observe:hermes -- --no-web-build
#
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # sentinel/probes/ebpf
REPO_ROOT="$(cd "$HERE/../../.." && pwd)"
IMG="${IMG:-agent-aegis-ebpf-test:latest}"
NAME=agent-aegis-sentinel-hermes
PORT="${AEGIS_PORT:-3800}"
STATE_HOST="${STATE_HOST:-/tmp/agent-aegis-hermes-live}"

cd "$REPO_ROOT"

if [ "${1:-}" != "--no-web-build" ]; then
  echo "==> building WebUI on host (so the read-only mount carries correct deps + dist)"
  ( cd web && npm install --no-audit --no-fund && npm run build )
fi

echo "==> building eBPF probe image $IMG (cached after first run)"
docker build -t "$IMG" "$HERE"

echo "==> (re)creating writable state dir on host: $STATE_HOST"
rm -rf "$STATE_HOST"; mkdir -p "$STATE_HOST"

echo "==> starting privileged container: Hermes-path eBPF observe + WebUI on :$PORT"
docker rm -f "$NAME" >/dev/null 2>&1 || true
docker run -d --name "$NAME" \
  --privileged --pid=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v "$REPO_ROOT":/repo:ro \
  -v "$STATE_HOST":/state \
  -e SENTINEL_STATE_DIR=/state \
  -e AEGIS_STATE_DIR=/state \
  -e AEGIS_STATIC_DIR=/repo/web/frontend/dist \
  -e AEGIS_APP=hermes \
  -e AEGIS_PORT="$PORT" \
  -p "${PORT}:${PORT}" \
  -w /repo \
  "$IMG" \
  bash -c '
    set -e
    echo "=== [1/2] Hermes RPC init starts eBPF (cat /etc/shadow observed, NOT blocked) ==="
    node /repo/sentinel/probes/ebpf/hermes-live.mjs
    echo "=== [2/2] starting WebUI (fed by /state/defense-events.jsonl) ==="
    exec node /repo/web/api/dist/index.js
  ' >/dev/null

echo "==> waiting for the Hermes observe run + WebUI to come up ..."
ok=0
for _ in $(seq 1 90); do
  if curl -fsS "http://localhost:${PORT}/api/v1/health" >/dev/null 2>&1; then ok=1; break; fi
  if ! docker ps --format '{{.Names}}' | grep -q "^${NAME}$"; then break; fi
  sleep 1
done

echo
echo "============== HERMES eBPF OBSERVE OUTPUT (container logs) =============="
docker logs "$NAME" 2>&1 | grep -E "init|OBSERVE|observed|native_blocked|native_observed|PASS|FAIL|WebUI|listening" || docker logs "$NAME" 2>&1 | tail -30
echo "======================================================================="
echo "observed events -> $STATE_HOST/defense-events.jsonl"

if [ "$ok" = "1" ]; then
  echo "WebUI is up: http://localhost:${PORT}  (Events page shows the observed detections)"
  echo "  events:  curl http://localhost:${PORT}/api/v1/events"
  command -v open >/dev/null 2>&1 && open "http://localhost:${PORT}" || true
else
  echo "WebUI did not become healthy. Inspect: docker logs ${NAME}"
  exit 1
fi
