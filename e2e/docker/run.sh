#!/usr/bin/env bash
# ClawGuard Docker E2E: docker-build image → monitor → labeled agent → local HTTPS target → assert.
# Go/BPF compile happens only inside `docker build` (never on the host).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${CLAWGUARD_IMAGE:-clawguard:e2e}"
NAME="${CLAWGUARD_NAME:-clawguard-e2e}"
HTTPS_NAME="${CLAWGUARD_HTTPS_NAME:-clawguard-e2e-https}"
NET="${CLAWGUARD_E2E_NET:-clawguard-e2e-net}"
MARKER="${CLAWGUARD_MARKER:-CLAWGUARD_E2E_SECRET_$(date +%s)}"
PORT="${CLAWGUARD_PORT:-18080}"
TIMEOUT_SEC="${CLAWGUARD_E2E_TIMEOUT:-90}"
SKIP_BUILD="${CLAWGUARD_SKIP_BUILD:-0}"

log() { printf '[e2e-docker] %s\n' "$*"; }
die() { printf '[e2e-docker] ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  docker rm -f "$NAME" "$HTTPS_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null || die "missing dependency: $1"; }
need docker
need curl

if [[ "$SKIP_BUILD" == "1" ]] && docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "skipping docker build (CLAWGUARD_SKIP_BUILD=1, image exists)"
else
  log "building image $IMAGE (Go/BPF compile inside Docker only)"
  docker build -t "$IMAGE" "$ROOT"
fi

cleanup
docker network create "$NET" >/dev/null

log "starting local HTTPS target ($HTTPS_NAME)"
docker run -d --name "$HTTPS_NAME" --network "$NET" python:3.11-slim bash -ec '
  apt-get update -qq && apt-get install -y -qq openssl >/dev/null
  openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem -days 1 -nodes -subj "/CN=clawguard-e2e-https" 2>/dev/null
  python - <<"PY"
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer

class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        _ = self.rfile.read(n)
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
httpd = HTTPServer(("0.0.0.0", 8443), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
' >/dev/null

# Wait until HTTPS accepts TCP (ignore cert errors)
deadline=$((SECONDS + TIMEOUT_SEC))
until docker exec "$HTTPS_NAME" python -c "import socket; s=socket.create_connection(('127.0.0.1',8443),2); s.close()" 2>/dev/null; do
  (( SECONDS < deadline )) || die "local HTTPS target not ready"
  sleep 1
done

log "starting monitor on :$PORT"
docker run -d --name "$NAME" \
  --privileged --pid=host \
  --network "$NET" \
  -p "${PORT}:8080" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CLAWGUARD_LABEL=clawguard.monitor=true \
  -e CLAWGUARD_DEBUG_UI=0 \
  -e CLAWGUARD_DEBUG=1 \
  "$IMAGE" >/dev/null

log "waiting for /metrics + version banner + file plugin"
deadline=$((SECONDS + TIMEOUT_SEC))
until curl -sf "http://127.0.0.1:${PORT}/metrics" | grep -q 'clawguard_'; do
  (( SECONDS < deadline )) || {
    docker logs "$NAME" 2>&1 | tail -50 >&2 || true
    die "metrics endpoint not ready"
  }
  sleep 1
done

ok_ver=0
ok_plug=0
while (( SECONDS < deadline )); do
  logs="$(docker logs "$NAME" 2>&1 || true)"
  if printf '%s\n' "$logs" | grep -q 'version='; then ok_ver=1; fi
  if printf '%s\n' "$logs" | grep -q 'plugin loaded name=file'; then ok_plug=1; fi
  if (( ok_ver == 1 && ok_plug == 1 )); then
    break
  fi
  sleep 1
done
if (( ok_ver != 1 || ok_plug != 1 )); then
  docker logs "$NAME" 2>&1 | tail -50 >&2 || true
  die "startup checks failed version_ok=$ok_ver plugin_ok=$ok_plug"
fi

before="$(curl -sf "http://127.0.0.1:${PORT}/metrics" | awk '/^clawguard_ssl_writes_total/{s+=$2} END{print s+0}')"

log "running labeled agent → https://${HTTPS_NAME}:8443/ (marker=$MARKER)"
docker run --rm --network "$NET" --label clawguard.monitor=true python:3.11-slim bash -ec "
  pip install -q requests urllib3
  python -c \"
import requests, urllib3
urllib3.disable_warnings()
requests.post(
  'https://${HTTPS_NAME}:8443/',
  data='${MARKER}',
  headers={'traceparent':'00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'},
  verify=False,
  timeout=30,
)
\"
"

log "waiting for ssl_writes increase + marker in logs/file"
deadline=$((SECONDS + TIMEOUT_SEC))
found_metric=0
found_log=0
found_file=0
after="$before"
while (( SECONDS < deadline )); do
  after="$(curl -sf "http://127.0.0.1:${PORT}/metrics" | awk '/^clawguard_ssl_writes_total/{s+=$2} END{print s+0}')"
  attached="$(curl -sf "http://127.0.0.1:${PORT}/metrics" | awk '/^clawguard_attached_targets /{print $2; exit}')"
  if awk -v a="$after" -v b="$before" 'BEGIN{exit !(a>b)}'; then
    found_metric=1
  fi
  if docker logs "$NAME" 2>&1 | grep -qF "$MARKER"; then
    found_log=1
  fi
  if docker exec "$NAME" sh -c "test -f /var/log/clawguard/plaintext.jsonl && grep -qF '$MARKER' /var/log/clawguard/plaintext.jsonl && grep -q clawguard_version /var/log/clawguard/plaintext.jsonl && grep -q '\"name\":\"file\"' /var/log/clawguard/plaintext.jsonl"; then
    found_file=1
  fi
  if (( found_metric == 1 && found_log == 1 && found_file == 1 )); then
    log "PASS metrics ssl_writes ${before}→${after} attached=${attached:-?} marker in logs+file (versioned)"
    exit 0
  fi
  sleep 1
done

docker logs "$NAME" 2>&1 | tail -100 >&2 || true
docker exec "$NAME" sh -c 'tail -5 /var/log/clawguard/plaintext.jsonl 2>/dev/null' >&2 || true
die "timeout: metric_ok=$found_metric log_ok=$found_log file_ok=$found_file (before=$before after=$after)"
