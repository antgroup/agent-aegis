#!/usr/bin/env bash
#
# End-to-end verification for the LSM enforce probe.
#
# Builds the runner Go binary inside a privileged Linux container, then
# runs verify-e2e.mjs which:
#  1. Triggers `cat /etc/shadow` (verdict + policy upsert)
#  2. Triggers `cat /etc/shadow` again (kernel-side deny + deny event)
#  3. Asserts both behaviours fired.
set -e

HERE="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
REPO_ROOT="$( cd "$HERE/../../.." && pwd )"
IMG="${IMG:-agent-aegis-lsm-test:latest}"

echo "==> building image $IMG"
docker build --progress=plain -t "$IMG" "$HERE"

echo "==> running verify-e2e.mjs inside container"
docker run --rm --privileged --pid=host \
  -v /sys/kernel/debug:/sys/kernel/debug \
  -v /sys/kernel/btf:/sys/kernel/btf:ro \
  -v "$REPO_ROOT":/repo \
  -w /repo \
  "$IMG" \
  bash -c "
    set -e
    mountpoint -q /sys/kernel/security || mount -t securityfs none /sys/kernel/security
    cat /sys/kernel/security/lsm
    # Ubuntu's bpftool wrapper insists on a kernel-version-matching package
    # that doesn't exist for OrbStack kernels — use the bundled binary.
    BPFTOOL_BIN=\$(find /usr/lib/linux-tools-* -name bpftool -type f | head -1)
    cd sentinel/probes/lsm/runner
    \$BPFTOOL_BIN btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
    go mod tidy
    make BPFTOOL=\$BPFTOOL_BIN
    cd /repo
    node sentinel/probes/lsm/verify-e2e.mjs
  "
