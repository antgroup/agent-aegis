# Dockerfile for AgentAegis uprobe probe end-to-end verification.
#
# Same base as the eBPF e2e — BCC + Python + Node. The uprobe variant adds
# a libssl install so SSL_* targets can be exercised when enabled.
FROM ubuntu:24.04
RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      bpfcc-tools python3-bpfcc xz-utils coreutils curl ca-certificates \
      nodejs libssl3 && \
    rm -rf /var/lib/apt/lists/*
