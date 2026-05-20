# Dockerfile for ClawAegis eBPF probe end-to-end verification.
#
# Builds a privileged-ready Ubuntu image with everything the probe needs:
#   - bpfcc-tools / python3-bpfcc: BCC runtime for the BPF programs
#   - xz-utils: needed by BCC to extract /sys/kernel/kheaders.tar.xz when
#     the kernel ships embedded headers (IKHEADERS); avoids the
#     "Unable to find kernel headers" failure on hosts whose /lib/modules
#     doesn't include build artifacts
#   - nodejs: drives sentinel + judge pipeline from verify-e2e.mjs
#
# Build:   docker build -t claw-aegis-ebpf-test .
# Run via the sibling verify-e2e.sh wrapper (handles mounts + privileges).
FROM ubuntu:24.04
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      bpfcc-tools python3-bpfcc xz-utils coreutils curl ca-certificates nodejs && \
    rm -rf /var/lib/apt/lists/*
