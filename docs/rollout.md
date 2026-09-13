# Rollout and self-health

How a new build reaches the fleet, and what is watched while it does.

```bash
scripts/deploy-observability.sh            # the dashboard
scripts/rollout.sh <image-tag>             # canary → gate → fleet
```

---

## The dashboard

Agent self-health is a different question from the telemetry the agent produces
about applications, with a different audience, so it has its own stack in its
own namespace — `deploy/k8s/observability/`. If the agent's namespace is
drained or misconfigured, the dashboard that would show you that is still up.

[`deploy/grafana/dashboards/agent-health.json`](../deploy/grafana/dashboards/agent-health.json),
provisioned from the file rather than created in a browser. Panels, and the
question each answers:

| Panel | The failure it makes visible |
| :--- | :--- |
| desired vs ready | **a missing agent** — this is the only panel that can show one, because an agent that is not running reports nothing, and absent metrics look exactly like a quiet node. It comes from the DaemonSet controller, not from the agent |
| targets attached, per node | an agent that is healthy and attached to nothing: it runs, serves metrics, reports Ready, and produces no telemetry |
| build per node | the rollout itself — promotion appears as a node changing series |
| ring buffer drops/s | the one failure that corrupts telemetry rather than delaying it |
| events received/s | the denominator: zero drops means nothing if the agent receives nothing |
| CPU and memory per node | what the agent costs the node it is observing, from cAdvisor rather than self-reported |
| restarts | a crash-looping agent reports Ready between crashes and its counters reset each time, so every other graph looks merely quiet |
| requests pending | rising means responses are not being matched, which appears downstream as spans that expire rather than complete |

Two things this cost to get right, both of which would have failed silently:

**cAdvisor returned 403.** Scraping through the API server
(`/api/v1/nodes/<name>/proxy/metrics/cadvisor`) is authorised as `nodes/proxy`,
not `nodes/metrics`. Without it the CPU and memory panels are simply empty,
which reads as an agent using no resources rather than as a permissions error.

**The datasource needs a fixed uid.** The dashboard JSON references
`uid: prometheus`; if the provisioned datasource does not declare it, every
panel renders empty — indistinguishable from a healthy fleet with nothing to
report.

---

## The rollout

`scripts/rollout.sh` is a script rather than a screen recording on purpose. A
recording shows that it worked once, on a machine you cannot inspect. This can
be re-run, it stops where it should when something is wrong, and it writes a
transcript that can be read afterwards by someone who was not watching.

```
canary (1 node)  →  60s settle  →  gate  →  fleet, one node at a time
                                     │
                                     └─ fails → stop, canary stays isolated
```

The settle is not padding. An agent that started ten seconds ago has attached
to whatever was running then and has no drop history at all, so gating on it
would pass regardless of what the build does.

---

## What happened when it ran

Two runs, both committed in [`rollouts/`](rollouts/).

### Run 1 — the gate stopped a broken build

[`rollouts/2026-09-13-failed-race.log`](rollouts/2026-09-13-failed-race.log)

```
3. Gate: is the canary node as healthy as a stable one
   canary   canary-ebpf-agent-gkx5t   ebpf-worker    restarts=1  drops=0  attached=1
   canary has restarted 1 times
   stable   stable-ebpf-agent-7jw7t   ebpf-worker2   restarts=0  drops=0  attached=3

FAIL — do not promote
   gate failed — stopping here, with 0.3.0-phase4 on the canary node only
```

The restart was a real crash, and the cause was a bug that had been in the agent
for three phases:

```
fatal error: concurrent map iteration and map write
correlate.(*Correlator).Expire   correlate.go:221
created by main.main             cmd/agent/main.go:132
```

The correlator was documented as single-goroutine — *"one correlator, driven
from the reader, so no locking is needed"* — which was true when written and
stopped being true when expiry moved onto a ticker. Three goroutines reached
that map in the running agent: the ring buffer reader in `Handle`, the timer in
`Expire`, and the metrics callback in `Pending` and `Stats`.

Every unit test passed throughout, and `go test -race` in CI found nothing,
because no test ran two of those goroutines at once. It took a real workload on
a real node to produce it — which is the argument for gating promotion on the
node's health rather than on whether the pod started.

Fixed with a mutex, emitting records outside the lock: `emit` ends in an OTLP
exporter, and holding the correlator's lock across a network client would turn
export latency into ring buffer back-pressure, which is the path that drops
events. `internal/correlate/concurrent_test.go` reproduces it — verified to
data-race on the previous code and pass on the current one.

One number in that run was **not** the agent's fault, and is worth stating
because it would be easy to present it as a catch: the canary node showed 75.6%
CPU against the stable node's 4.5%. That was a busy-loop client pod pinned to
the canary node, left over from generating dashboard data. The arms have to be
equal for the comparison to mean anything; the workload now runs on both.

### Run 2 — promotion

[`rollouts/2026-09-13-promoted.log`](rollouts/2026-09-13-promoted.log)

```
2. 18:14:24Z  Canary: 0.3.1-phase4 onto the labelled node only
   canary running 0.3.1-phase4
   settling for 60s before measuring

3. 18:15:26Z  Gate: is the canary node as healthy as a stable one
   gate passed

4. 18:16:01Z  Fleet: the same build to everything else
   daemon set "stable-ebpf-agent" successfully rolled out

5. 18:16:05Z  Result
   stable: ...:0.3.1-phase4
   canary: ...:0.3.1-phase4
   PASS — 0.3.1-phase4 on every node, promoted only after the gate
```

Both releases end on the same build, which is the correct end state: the canary
label stays on its node so the next rollout has somewhere to land, and no node
is left running something different from the rest of the fleet.

Total elapsed: **101 seconds**, of which 60 was the deliberate settle.

---

## Rolling back

The gate stops before the fleet is touched, so a rollback is one release:

```bash
helm upgrade canary deploy/helm/ebpf-agent -n ebpf-observability \
  -f deploy/helm/ebpf-agent/values-canary.yaml --set image.tag=<previous>
```

The script prints this line itself when the gate fails, with the release and
paths filled in, because the moment you need it is the moment you are least
inclined to look them up.
