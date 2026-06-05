#!/usr/bin/env bash
#
# End-to-end verification for the uprobe probe.
#
# Same shape as the eBPF e2e (sibling probes/ebpf/verify-e2e.sh): builds a
# privileged Linux container and runs verify-e2e.mjs inside it. Exits 0 only
# when the native judge produces a block verdict for `cat /etc/shadow`,
# observed via uprobe on libc:openat.
set -e

HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$HERE/../../.." && pwd )"
IMG="${IMG:-claw-aegis-uprobe-test:latest}"

echo "==> building image $IMG (cached after first run)"
docker build --progress=plain -t "$IMG" "$HERE"

echo "==> running verify-e2e.mjs inside container"
docker run --rm --privileged --pid=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v "$REPO_ROOT":/repo:ro \
  -w /repo \
  "$IMG" \
  node /repo/sentinel/probes/uprobe/verify-e2e.mjs
