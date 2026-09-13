# The agent image.
#
# Two stages. The builder compiles the BPF objects and links them into the Go
# binary; the runtime stage holds the binary and nothing else — no shell, no
# package manager, no clang. A node-level agent holding CAP_SYS_ADMIN is the
# last place to leave a toolchain lying around.
#
# vmlinux.h is NOT generated here. It is rendered from a running kernel's BTF,
# and a container build has no kernel to read. It comes from the build context
# instead, produced by `make vmlinux` on the build host — which is why `make
# image` depends on it. CO-RE is what makes this sound: the offsets baked in
# here are relocated at load time against the *target* node's BTF, so the
# kernel that supplied vmlinux.h does not have to match the kernel that runs
# the agent. That property is the subject of ADR-004 and is tested in
# docs/kernel-matrix.md.

# Pinned to the go directive in go.mod. A newer base would work; an older one
# fails at `go mod download` with GOTOOLCHAIN=local, which is the right failure
# but an easy one to spend time on.
#
# trixie, not bookworm, for libbpf: the BPF_UPROBE and BPF_URETPROBE macros the
# probes are written against arrived in libbpf 1.2, and bookworm ships 1.1.2.
# Against that header the programs fail to compile with "expected identifier",
# which reads like a syntax error in our own C rather than a missing macro.
FROM golang:1.27-trixie AS builder

# clang with the BPF backend, and libbpf's headers for bpf_helpers.h.
# bpftool is absent on purpose: the one thing it would be used for, generating
# vmlinux.h, cannot happen in this stage.
RUN apt-get update && apt-get install -y --no-install-recommends \
      clang \
      llvm \
      libbpf-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first, so that editing a .go file does not re-download them.
COPY go.mod go.sum ./
RUN go mod download

COPY . .

# bpf/vmlinux.h is gitignored, so this fails loudly when the build context was
# assembled without it rather than falling through to an obscure clang error
# about a missing include.
RUN test -f bpf/vmlinux.h || { \
      echo "ERROR: bpf/vmlinux.h missing from the build context."; \
      echo "       Run 'make vmlinux' on a host with CONFIG_DEBUG_INFO_BTF=y,"; \
      echo "       or build through 'make image', which does it for you."; \
      exit 1; }

# go generate runs bpf2go: clang compiles each bpf/*.bpf.c to an ELF object and
# emits Go bindings that embed it. The objects ship inside the binary, so the
# runtime stage needs no BPF files on disk.
#
# Scoped to ./internal/... rather than ./... on purpose. test/ carries its own
# generate directives for the verifier and toolchain experiments, which are a
# development concern, take the longest to compile, and would make the image
# build depend on them continuing to compile against whatever clang this base
# image ships.
RUN go generate ./internal/...

# Static, because the runtime stage has no libc.
ARG VERSION=dev
RUN CGO_ENABLED=0 go build \
      -trimpath \
      -ldflags "-s -w" \
      -o /out/agent ./cmd/agent

# ---------------------------------------------------------------------------
# distroless/static: a root filesystem with CA certificates, timezone data and
# nothing executable. There is no shell in this image, so an attacker who
# achieves execution inside it has no interactive foothold — which matters more
# than usual for a container that runs with CAP_SYS_ADMIN and hostPID.
#
# Not the :nonroot variant. The agent reads other processes' files through
# /proc/<pid>/root, which needs uid 0; see docs/capabilities.md.
FROM gcr.io/distroless/static-debian12

COPY --from=builder /out/agent /agent

# Metrics. Traces leave over OTLP and open no port.
EXPOSE 9464

ENTRYPOINT ["/agent"]
