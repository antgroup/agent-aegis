#!/usr/bin/env bash
#
# End-to-end verification for the eBPF probe.
#
# Builds (idempotent, hits docker layer cache after the first run) a
# privileged Linux container and runs verify-e2e.mjs inside it. Exits 0
# only if the native:sensitive-path judge produces a block verdict for
# `cat /etc/shadow`, which proves the full pipeline works on Linux:
#
#   eBPF tracepoints → probe.py JSONL → loader.ts → sentinel → native
#   judge → block verdict → JSONL store.
#
# Requirements:
#   - Docker daemon (OrbStack on macOS works)
#   - Linux kernel exposed via the Docker daemon with /sys/kernel/debug
#     readable (any modern OrbStack / Docker Desktop / native Linux)
#   - Repo built (`npm run build`) so the .js artifacts exist
#
# Env overrides:
#   IMG=…    image tag (default: agent-aegis-ebpf-test:latest)
#
set -e

HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$HERE/../../.." && pwd )"
IMG="${IMG:-agent-aegis-ebpf-test:latest}"

echo "==> building image $IMG (cached after first run)"
docker build --progress=plain -t "$IMG" "$HERE"

echo "==> running verify-e2e.mjs inside container"
docker run --rm --privileged --pid=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v "$REPO_ROOT":/repo:ro \
  -w /repo \
  "$IMG" \
  node /repo/sentinel/probes/ebpf/verify-e2e.mjs
