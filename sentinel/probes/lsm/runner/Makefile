# Build the unified ClawAegis sentinel runner.
#
# One Go binary with three modes (--mode=ebpf|uprobe|lsm), each backed by a
# CO-RE BPF object compiled from bpf/*.bpf.c at build time.
#
# Outputs:
#   bpf/lsm.bpf.o         LSM hooks for enforce mode
#   bpf/exec.bpf.o        tracepoint + uprobe programs for observe modes
#   dist/sentinel-runner  embedded ELF that go:embeds both .bpf.o files
#
# Targets:
#   make          (default) → bpf + go
#   make bpf      → just the .o files
#   make go       → just the Go binary
#   make clean    → remove generated files
#   make vmlinux  → regenerate bpf/vmlinux.h from /sys/kernel/btf/vmlinux
#
# Requirements: clang, llvm-strip, bpftool (for vmlinux.h), go ≥ 1.22
ARCH ?= $(shell uname -m | sed -e 's/x86_64/x86/' -e 's/aarch64/arm64/')
CLANG ?= clang
LLVM_STRIP ?= llvm-strip
BPFTOOL ?= bpftool

BPF_CFLAGS = -O2 -g -Wall -target bpf -D__TARGET_ARCH_$(ARCH) \
             -I$(CURDIR)/bpf

.PHONY: all bpf go clean vmlinux

all: bpf go

bpf: bpf/lsm.bpf.o bpf/exec.bpf.o

bpf/%.bpf.o: bpf/%.bpf.c bpf/vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@
	$(LLVM_STRIP) -g $@

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

go: dist/sentinel-runner

dist/sentinel-runner: main.go bpf/lsm.bpf.o bpf/exec.bpf.o
	@mkdir -p dist
	CGO_ENABLED=0 go build -ldflags="-s -w" -o dist/sentinel-runner .
	@ln -sf sentinel-runner dist/lsm-runner

clean:
	rm -f bpf/*.bpf.o dist/sentinel-runner dist/lsm-runner
	rmdir dist 2>/dev/null || true
