# Makefile — the build pipeline for eBPF (Phase 1, WBS task 1).
#
# Everything here runs INSIDE the Linux VM. `make` on macOS will fail loudly,
# on purpose: silently producing something unloadable is worse than erroring.

SHELL := /bin/bash
.DEFAULT_GOAL := help

# ---------------------------------------------------------------------------
# Toolchain
# ---------------------------------------------------------------------------
CLANG    ?= clang
BPFTOOL  ?= bpftool
GO       ?= go
VMLINUX  := bpf/vmlinux.h
BTF_SRC  := /sys/kernel/btf/vmlinux

# BPF target endianness. bpfel = little-endian (x86_64, arm64, most of the
# world). bpfeb = big-endian (s390x). Getting this wrong produces an object the
# kernel loads but that reads garbage from every struct field.
BPF_TARGET ?= bpfel

# CFLAGS for BPF compilation. Each flag earns its place:
#   -O2        : REQUIRED, not optional. -O0 emits patterns the verifier
#                rejects (it can't prove bounds through unoptimised code).
#   -g         : emit BTF for our own program. Needed for CO-RE relocations
#                and for readable verifier errors.
#   -Wall -Werror : a warning in BPF C is usually a verifier failure in waiting.
#   -Ibpf      : so #include "vmlinux.h" resolves.
#   -D__TARGET_ARCH_* : bpf_tracing.h uses this to pick the right PT_REGS_PARMn
#                macros for the target ABI.
ARCH := $(shell uname -m | sed 's/x86_64/x86/; s/aarch64/arm64/')
BPF_CFLAGS := -O2 -g -Wall -Werror -target bpf -D__TARGET_ARCH_$(ARCH) -Ibpf

# ---------------------------------------------------------------------------
.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_%.-]+:.*?## ' $(MAKEFILE_LIST) \
	  | awk 'BEGIN{FS=":.*?## "}{printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

.PHONY: linux-only
linux-only:
	@[ "$$(uname -s)" = "Linux" ] || { \
	  echo "ERROR: eBPF builds must run inside the Linux VM."; \
	  echo "       limactl shell ebpf   (see scripts/lima-ebpf.yaml)"; exit 1; }

.PHONY: check
check: ## Verify the kernel/toolchain supports everything we need
	@bash scripts/check-env.sh

# ---------------------------------------------------------------------------
# vmlinux.h — the CO-RE foundation
# ---------------------------------------------------------------------------
# The running kernel exposes its complete type information as BTF at
# /sys/kernel/btf/vmlinux. bpftool renders that binary blob into a single C
# header containing every kernel struct.
#
# WHY THIS MATTERS (ADR-004): our C code says `sk->__sk_common.skc_daddr`.
# That field sits at a different byte offset in different kernel versions.
# Compiled with -g, clang records a CO-RE *relocation* instead of a fixed
# offset, and libbpf/cilium-ebpf patches in the correct offset at LOAD time
# using the target kernel's own BTF. One binary, many kernels — which is NFR5.
#
# This header is gitignored: it is regenerable and machine-specific.
$(VMLINUX): | linux-only
	@echo ">> generating $(VMLINUX) from $(BTF_SRC)"
	@[ -r $(BTF_SRC) ] || { \
	  echo "ERROR: $(BTF_SRC) not readable."; \
	  echo "       Kernel lacks CONFIG_DEBUG_INFO_BTF=y — CO-RE is impossible here."; \
	  echo "       This is exactly the FR8 'fail closed with a clear error' case."; \
	  exit 1; }
	@$(BPFTOOL) btf dump file $(BTF_SRC) format c > $@
	@echo ">> $(VMLINUX) is $$(wc -l < $@) lines"

.PHONY: vmlinux
vmlinux: $(VMLINUX) ## Generate bpf/vmlinux.h from the running kernel's BTF

.PHONY: vmlinux-force
vmlinux-force: ## Regenerate vmlinux.h even if it exists
	@rm -f $(VMLINUX) && $(MAKE) vmlinux

# ---------------------------------------------------------------------------
# Build
# ---------------------------------------------------------------------------
.PHONY: generate
generate: $(VMLINUX) ## Run bpf2go: compile .bpf.c -> BPF ELF + Go bindings
	@$(GO) generate ./...

.PHONY: build
build: generate ## Build the agent binary
	@mkdir -p bin
	@CGO_ENABLED=0 $(GO) build -o bin/agent ./cmd/agent
	@echo ">> bin/agent"

# ---------------------------------------------------------------------------
# Container image
# ---------------------------------------------------------------------------
IMAGE   ?= ghcr.io/sachin-680/ebpf-observability-agent
TAG     ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Depends on vmlinux.h because a container build cannot read a kernel's BTF:
# there is no /sys to read it from. It is rendered here and shipped in the
# build context. CO-RE means the kernel that supplies it need not match the
# kernel that runs the agent (ADR-004).
.PHONY: image
image: $(VMLINUX) ## Build the agent container image
	@docker build --build-arg VERSION=$(TAG) -t $(IMAGE):$(TAG) -t $(IMAGE):latest .
	@echo ">> $(IMAGE):$(TAG)"

# Needs a cluster with both releases installed; see deploy/helm/ebpf-agent.
.PHONY: gate-canary
gate-canary: ## Decide whether the canary is safe to promote
	@bash scripts/gate-canary.sh

.PHONY: verify
verify: ## Fast check: build, format, vet, and every test that needs no load (~60s)
	@bash scripts/verify.sh

.PHONY: verify-toolchain
verify-toolchain: generate ## Load a probe into the kernel to prove the pipeline works (needs sudo)
	@sudo env PATH=$(PATH) $(GO) test ./test/toolchain/ -v

.PHONY: test
test: ## Run Go unit tests (parser, correlation — no kernel needed)
	@$(GO) test ./internal/... ./test/unit/...

.PHONY: lint
lint: ## gofmt + go vet
	@gofmt -l . | tee /dev/stderr | (! read)
	@$(GO) vet ./...

.PHONY: clean
clean: ## Remove build artifacts (keeps vmlinux.h)
	@rm -rf bin dist
	@find . -name '*_bpfel*.go' -o -name '*_bpfeb*.go' -o -name '*.bpf.o' | xargs -r rm -f

.PHONY: trace
trace: ## Tail the kernel trace pipe (where bpf_printk output lands)
	@sudo cat /sys/kernel/tracing/trace_pipe 2>/dev/null \
	  || sudo cat /sys/kernel/debug/tracing/trace_pipe
