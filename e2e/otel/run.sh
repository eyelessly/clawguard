#!/usr/bin/env bash
# Docker E2E with OpenTelemetry Collector (file exporter) asserting marker in exported logs.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${CLAWGUARD_IMAGE:-clawguard:e2e}"
NAME="${CLAWGUARD_NAME:-clawguard-e2e-otel}"
COLLECTOR="${CLAWGUARD_COLLECTOR:-clawguard-otel-collector}"
MARKER="${CLAWGUARD_MARKER:-CLAWGUARD_OTEL_SECRET_$(date +%s)}"
PORT="${CLAWGUARD_PORT:-18082}"
TIMEOUT_SEC="${CLAWGUARD_E2E_TIMEOUT:-120}"
NET="${CLAWGUARD_E2E_NET:-clawguard-e2e-net}"
OUT_DIR="${TMPDIR:-/tmp}/clawguard-otel-e2e-$$"

log() { printf '[e2e-otel] %s\n' "$*"; }
die() { printf '[e2e-otel] ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  docker rm -f "$NAME" "$COLLECTOR" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$OUT_DIR"
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null || die "missing dependency: $1"; }
need docker

log "building image $IMAGE"
docker build -t "$IMAGE" "$ROOT"

mkdir -p "$OUT_DIR"
cat > "$OUT_DIR/config.yaml" <<'YAML'
receivers:
  otlp:
    protocols:
      http:
        endpoint: 0.0.0.0:4318
exporters:
  file:
    path: /out/clawguard-logs.json
    rotation:
      max_megabytes: 10
service:
  pipelines:
    logs:
      receivers: [otlp]
      exporters: [file]
YAML

docker network rm "$NET" >/dev/null 2>&1 || true
docker rm -f "$NAME" "$COLLECTOR" >/dev/null 2>&1 || true
docker network create "$NET" >/dev/null

log "starting otel collector"
docker run -d --name "$COLLECTOR" --network "$NET" \
  -v "$OUT_DIR/config.yaml:/etc/otelcol/config.yaml:ro" \
  -v "$OUT_DIR:/out" \
  otel/opentelemetry-collector:0.114.0 \
  --config=/etc/otelcol/config.yaml >/dev/null

log "starting clawguard with OTLP export"
docker run -d --name "$NAME" --network "$NET" \
  --privileged --pid=host \
  -p "${PORT}:8080" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CLAWGUARD_LABEL=clawguard.monitor=true \
  -e CLAWGUARD_DEBUG_UI=0 \
  -e OTEL_EXPORTER_OTLP_ENDPOINT="http://${COLLECTOR}:4318" \
  -e OTEL_EXPORTER_OTLP_INSECURE=1 \
  -e OTEL_SERVICE_NAME=clawguard \
  "$IMAGE" >/dev/null

deadline=$((SECONDS + TIMEOUT_SEC))
until curl -sf "http://127.0.0.1:${PORT}/metrics" | grep -q clawguard_; do
  (( SECONDS < deadline )) || die "monitor not ready"
  sleep 1
done

log "running labeled agent (marker=$MARKER)"
docker run --rm --label clawguard.monitor=true python:3.11-slim bash -ec "
  pip install -q requests
  python -c \"import requests; requests.post('https://httpbin.org/post', data='$MARKER', headers={'traceparent':'00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'}, timeout=30)\"
"

deadline=$((SECONDS + TIMEOUT_SEC))
while (( SECONDS < deadline )); do
  if grep -R -qF "$MARKER" "$OUT_DIR" 2>/dev/null; then
    log "PASS OTel collector file export contains marker"
    exit 0
  fi
  # protobuf/jsonl may embed the string; also check clawguard still saw it
  if docker logs "$NAME" 2>&1 | grep -qF "$MARKER" && [[ -f "$OUT_DIR/clawguard-logs.json" ]]; then
    # file exists and clawguard captured — wait a bit more for exporter flush
    :
  fi
  sleep 2
done

docker logs "$NAME" 2>&1 | tail -40 >&2 || true
ls -la "$OUT_DIR" >&2 || true
die "collector export never contained marker $MARKER"
