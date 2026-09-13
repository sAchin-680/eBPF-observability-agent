---
name: Feature request
about: Propose a capability the agent does not have
labels: enhancement
---

## The problem

<!-- What cannot be observed today, and why that matters. Not the solution. -->

## Is it already out of scope?

The README lists what this project deliberately does not do — HTTP/2 and gRPC,
statically linked TLS, database wire protocols, cross-service context
propagation — each for a stated reason. If this overlaps one of them, say what
has changed about the reasoning rather than restating the request.

## What it would cost

<!-- Rough is fine. Kernel-side or userspace? Does it need a new probe point, a
     new capability, or a kernel version this project does not yet require?
     Anything that widens the privilege set needs the measurement ADR-006
     describes. -->

## How it would be verified

<!-- The hardest part in this repository is usually not making something work
     but proving it did not silently stop working. What test fails if this
     regresses? -->
