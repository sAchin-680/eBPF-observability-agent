# Local observability stack

Tempo, Prometheus and Grafana, run beside the agent rather than around it. The
agent needs a real kernel and elevated privileges; these three are ordinary
services it exports to over the network, exactly as it would export to a
cluster-wide backend.

## Running

```bash
docker compose -f deploy/compose/compose.yaml up -d
```

Then start the agent, which exports to this stack by default:

```bash
sudo ./bin/agent
```

## Where to look

| | |
| :--- | :--- |
| Traced services | <http://127.0.0.1:3000/d/ebpf-services/traced-services> |
| Diagnosis | <http://127.0.0.1:3000/d/ebpf-diagnosis/diagnosis> |
| Prometheus | <http://127.0.0.1:9090> |
| Agent metrics | <http://127.0.0.1:9464/metrics> |

**Use `127.0.0.1`, not `localhost`.** When the stack runs inside a VM the
forwarded port is bound on IPv4 only, while `localhost` resolves to `::1`
first. Anything already listening on the same port over IPv6 — a Grafana
installed on the host, for instance — will receive the request instead, and
will correctly report that it has no such dashboard.

Grafana has no login: this stack holds no real data, and a login prompt is only
an obstacle to a demonstration.

## Dashboards

Provisioned from `grafana/dashboards/*.json` and not editable in the UI, so that
what is deployed is what is in version control. Editing one means editing the
file.

**Traced services** — rate, errors and duration per service. The service list is
populated by a query, not by configuration: services appear because they were
observed.

**Diagnosis** — the same data ranked, so that the worst service is the top row
rather than something to be found by reading a graph.

## Two things the panels are careful about

**Span kind.** The agent observes both ends of a local call: the client writing
a request and the server reading it. Counting both doubles every request, so
the dashboards default to `server` and offer `client` as a separate view of the
same traffic.

**Uncaptured responses are not errors.** A request whose response was never
observed has an unknown outcome, not a failed one. These are excluded from the
error rate and reported separately as a coverage gap, so that a limitation of
the agent is never presented as a fault in a service.
