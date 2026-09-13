# Continuous integration

What is checked, and what each check is protecting against. Nothing here is a
check because a checklist suggested it: every gate exists because the failure it
catches has either happened in this repository or is invisible without it.

---

## Two tiers

Fast gates answer a pull request in a few minutes. Anything that needs another
kernel, repetition, or minutes of load runs separately.

| Workflow | When | What it protects |
| :--- | :--- | :--- |
| [`ci.yml`](../.github/workflows/ci.yml) | every push and PR | the Go side compiles, is formatted, passes unit tests under the race detector, and the deployment manifests still agree |
| [`ebpf.yml`](../.github/workflows/ebpf.yml) | every push and PR | the BPF objects carry what CO-RE needs, and load on kernels other than the build kernel |
| [`security.yml`](../.github/workflows/security.yml) | push, PR, weekly | no reachable known vulnerabilities; the privilege set has not quietly grown |
| [`nightly.yml`](../.github/workflows/nightly.yml) | nightly | the parser survives arbitrary input; the agent leaks no kernel objects across restarts |
| [`release.yml`](../.github/workflows/release.yml) | on a tag | a tag cannot become a release until its artifacts load on every supported kernel |

---

## The one that matters most

`ebpf.yml` compiles **once** and runs those same artifacts on 5.15, 6.1 and 6.6,
booted in QEMU from the kernel images Cilium publishes.

Compiling once is the point. NFR5 claims that one binary works across kernels —
a matrix that rebuilds per kernel tests the toolchain instead, and passes
whether or not the claim holds. The build job uploads the binaries; the matrix
jobs are forbidden from rebuilding them, and each prints the checksum of what it
ran.

```
kernel 5.15.219  (x86_64)
  PASS  BTF present                      3625992 bytes
  PASS  toolchain                        1 subtests
  PASS  verifier                         9 subtests
  PASS  agent loads and attaches         0 targets on this VM
```

Zero targets is the correct result there: a CI VM runs no TLS workload. The
assertion is that the programs loaded and relocated against *that* kernel's
types, not that anything was captured.

### Object inspection, before anything is loaded

[`scripts/ci/verify-objects.sh`](../scripts/ci/verify-objects.sh) checks each
compiled object for `.BTF` and `.BTF.ext`. This guards a failure that is
completely silent: drop `-g` from the compile flags and every object still
builds, still loads on the machine that built it, and no longer carries
relocations. The agent would work in development and break on the first node
running a different kernel.

The check found a bug in itself on first run. `readelf -S` prints `[ 1] .text`
and `[10] .text`, so the section name is the second field in one case and the
third in the other — column indexing reported the wrong thing for every object
with ten or more sections, and three objects "failed" that were fine.

---

## What the gates have already caught

Recorded because a gate that has never caught anything is indistinguishable
from one that cannot.

**A vulnerable BPF loader.** `govulncheck` reported `cilium/ebpf@v0.16.0` as
affected, fixed in v0.22.0. Upgrading required one API change: `ProgramOptions.
LogSize` was removed in v0.18 — the library now grows the verifier log buffer
itself, which is what the verifier test had been doing by hand.

**A development toolchain three months behind.** The stdlib vulnerabilities
reported alongside it were not dependencies at all: the build used the exact
patch release named in `go.mod`, so every `crypto/tls` and `crypto/x509` fix
since was missing from the binary. This agent links both, because it exports
over TLS. CI now builds with the current release, and the VM definition was
bumped too.

**A coverage floor set from a broken measurement.** The floor was 38%, taken
from a local run that reported 40.1%. CI reported 16.6% for the same command:
the local run had silently excluded two packages that produce no coverage
profile, and the honest figure was less than half the assumed one. The gate was
removed rather than lowered — see below.

---

## What was removed, and why

A gate that reports its own version skew, duplicates another, or measures noise
is worse than no gate: it trains people to ignore a red check.

| Removed | Why |
| :--- | :--- |
| coverage floor | the threshold came from a mismeasurement, and the number it guards is dominated by kernel-interaction code that `go test` cannot reach at all |
| staticcheck | cannot read the export data of a Go toolchain newer than its own release, and this repository must build with the current Go for the security fixes. It reported version skew, not bugs. `go vet` ships with the toolchain and cannot drift from it |
| CodeQL | on a codebase this size it duplicated `go vet` and `govulncheck`, and cannot analyse the part that is actually dangerous — the C runs in the kernel, where the verifier is a far stricter analyser |
| gitleaks | GitHub runs secret scanning natively on public repositories; two tools reporting the same finding is one tool too many |
| dependency review | Dependabot opens the pull request and `govulncheck` fails it if the dependency is reachable and vulnerable. The third check added a gate without adding a failure it could catch |
| benchmark regression | on a shared runner the variance exceeded the regressions worth catching. The benchmarks remain and are run by hand on a quiet machine, which is the only place their numbers mean anything |
| extended kernel matrix | 5.4 and 5.10 are below the supported floor, and "stable" reports on a kernel nobody runs yet |

---

## Local equivalents

Most of this runs locally, faster, before pushing:

```bash
make verify          # format, vet, unit tests, kernel tests, manifest drift — ~5s
make gate-canary     # the canary promotion gate, needs a cluster
bash scripts/ci/verify-objects.sh
sudo bash scripts/ci/leak-check.sh bin/agent 10
```
