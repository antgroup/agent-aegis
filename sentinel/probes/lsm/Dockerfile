# Dockerfile for ClawAegis LSM enforce e2e.
#
# Builds the Go runner inside the container so we don't depend on the host
# toolchain. Requires kernel ≥ 5.7 with CONFIG_BPF_LSM=y at runtime —
# OrbStack / Docker Desktop usually meet this on recent versions.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      ca-certificates curl xz-utils coreutils \
      clang llvm libelf-dev libelf1 zlib1g-dev pkg-config make \
      linux-tools-common linux-tools-generic bpfcc-tools nodejs \
      libbpf-dev golang-1.22 && \
    rm -rf /var/lib/apt/lists/*
ENV PATH=/usr/lib/go-1.22/bin:$PATH
