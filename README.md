# ClawGuard

![ClawGuard](clawguard-logo.png)

**Cloud-native eBPF sidecar for AI agent observability** — capture TLS plaintext *before encryption* (OpenSSL `SSL_write` / `SSL_write_ex`) from outside the agent image. No MITM, no agent Dockerfile changes.

Primary ops surface: **Prometheus metrics + Grafana**. Optional: **OpenTelemetry Logs** and a local **Debug Console**.

---

## Quick Start (recommended): Kubernetes + Grafana

### 1. Deploy the DaemonSet

```bash
kubectl apply -f deploy/kubernetes/rbac.yaml
kubectl apply -f deploy/kubernetes/daemonset.yaml
```

ClawGuard watches Pods on each node with annotation:

```yaml
metadata:
  annotations:
    clawguard.io/monitor: "true"
```

See [`deploy/kubernetes/example-monitored-pod.yaml`](deploy/kubernetes/example-monitored-pod.yaml).

### 2. Scrape `/metrics`

Each DaemonSet pod exposes Prometheus metrics on **`:8080/metrics`** (Service annotations included for common scrape setups).

| Metric | Type | Meaning |
|--------|------|---------|
| `clawguard_ssl_writes_total` | Counter | Reassembled SSL writes (`hook`, `truncated`) |
| `clawguard_ssl_write_bytes_total` | Counter | Captured plaintext bytes |
| `clawguard_reassembly_timeouts_total` | Counter | Dropped incomplete reassemblies |
| `clawguard_attached_targets` | Gauge | Currently attached targets |
| `clawguard_attach_errors_total` | Counter | Discover/attach failures |

### 3. Import the official Grafana dashboard

Import [`deploy/grafana/clawguard-dashboard.json`](deploy/grafana/clawguard-dashboard.json) into Grafana (Prometheus datasource). Panels cover write rate, bytes/sec, attached targets, timeouts, and attach errors.

### 4. Optional: OpenTelemetry Logs

Set on the DaemonSet:

```yaml
- name: OTEL_EXPORTER_OTLP_ENDPOINT
  value: http://otel-collector:4318
- name: OTEL_SERVICE_NAME
  value: clawguard
- name: OTEL_EXPORTER_OTLP_INSECURE
  value: "1"
```

Each reassembled write becomes an OTLP **Log** (body = payload preview). If the HTTP plaintext contains a W3C `traceparent` header, ClawGuard attaches `trace_id` / `span_id` (best-effort user-space parse; eBPF-native Trace ID extraction is a later enhancement).

---

## What ClawGuard does

[**OpenClaw**](https://openclaw.ai/), [**nanobot**](https://github.com/HKUDS/nanobot), and similar agent stacks often run in containers with tools, API keys, and user context — and can leak PII or credentials over HTTPS. ClawGuard gives operators a **zero-intrusive** view of plaintext about to hit TLS.

- Hooks **OpenSSL** inside selected containers/Pods (`SSL_write` / `SSL_write_ex`).
- **No TLS MITM**, no extra CA, no agent source changes.
- Selection: Docker **labels** or Kubernetes **annotations**.
- Runtime: **Linux** only (host or Docker Desktop VM). Needs privileged eBPF.

---

## Docker Compose / single-host

```bash
docker pull eyelessly/clawguard:latest
docker rm -f clawguard 2>/dev/null
docker run -d --name clawguard \
  --privileged --pid=host \
  -p 8080:8080 \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CLAWGUARD_LABEL=clawguard.monitor=true \
  -e CLAWGUARD_DEBUG_UI=0 \
  eyelessly/clawguard:latest
```

Label agents:

```bash
docker run --label clawguard.monitor=true ...
```

Verify metrics:

```bash
curl -s localhost:8080/metrics | grep clawguard_
```

Smoke test:

```bash
docker run --rm --label clawguard.monitor=true python:3.11-slim bash -ec '
  pip install -q requests
  python -c "import requests; requests.post(\"https://httpbin.org/post\", data=\"MY_SECRET_PASSWORD_123\")"
'
```

### Local Debug Console

The built-in Wireshark-style UI is optional for single-machine debugging:

- Default: UI + WebSocket on `:8080` (in addition to `/metrics`).
- Production / K8s: set `CLAWGUARD_DEBUG_UI=0` to serve only `/metrics`.

![ClawGuard UI](clawguard-ui.png)

---

## Configuration

| Env | Default | Description |
|-----|---------|-------------|
| `CLAWGUARD_LABEL` | _(none)_ | Docker mode: `key=value` pairs (AND). Example: `clawguard.monitor=true` |
| `CLAWGUARD_POD_ANNOTATION` | `clawguard.io/monitor=true` | K8s mode: single `key=value` annotation filter |
| `NODE_NAME` | _(required in K8s)_ | Downward API node name |
| `CLAWGUARD_DEBUG_UI` | on | Set `0` / `false` / `off` to disable UI/WS |
| `CLAWGUARD_DEBUG` | _(off)_ | Verbose attach/reassembly logs |
| `CLAWGUARD_PAYLOAD_PREVIEW_MAX` | `16384` | Log/OTel body preview cap |
| `OTEL_EXPORTER_OTLP_ENDPOINT` | _(empty = off)_ | Enable OTLP HTTP log export |
| `OTEL_SERVICE_NAME` | `clawguard` | OTel resource service name |
| `OTEL_EXPORTER_OTLP_INSECURE` | _(off)_ | Allow plain HTTP to collector |
| `DOCKER_HOST` | `unix:///var/run/docker.sock` | Docker engine endpoint |

Mode selection: if `KUBERNETES_SERVICE_HOST` is set → **Kubernetes**; otherwise → **Docker**.

---

## Build from source

```bash
docker build -t clawguard:local .
# or
make docker-build IMAGE=clawguard:local
```

Native Linux (requires `clang`, `llvm`, `libbpf-dev`, Go 1.22+):

```bash
make build
sudo ./bin/clawguard
```

---

## Limitations

- **OpenSSL dynamic linking** (plus Node static-OpenSSL executable fallback). Not BoringSSL / typical static Go `crypto/tls`.
- Capture capped at **16384 bytes** per logical write; reassembly TTL **2s**.
- Trace correlation via plaintext `traceparent` only (no eBPF Trace ID extraction yet).
