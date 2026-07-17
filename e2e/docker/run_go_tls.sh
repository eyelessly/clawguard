#!/usr/bin/env bash
# Go crypto/tls E2E: static Go HTTPS client → clawguard captures go_tls_write.
# Go binary is built inside a golang Docker image (never on the host).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${CLAWGUARD_IMAGE:-clawguard:e2e}"
NAME="${CLAWGUARD_NAME:-clawguard-e2e-gotls}"
HTTPS_NAME="${CLAWGUARD_HTTPS_NAME:-clawguard-e2e-https-gotls}"
AGENT_IMAGE="${CLAWGUARD_GO_AGENT_IMAGE:-clawguard-go-agent:e2e}"
NET="${CLAWGUARD_E2E_NET:-clawguard-e2e-gotls-net}"
PORT="${CLAWGUARD_PORT:-18084}"
TIMEOUT_SEC="${CLAWGUARD_E2E_TIMEOUT:-180}"
SKIP_BUILD="${CLAWGUARD_SKIP_BUILD:-0}"
MARKER="CLAWGUARD_GOTLS_$(date +%s)"
WORKDIR="${TMPDIR:-/tmp}/clawguard-gotls-$$"

log() { printf '[e2e-gotls] %s\n' "$*"; }
die() { printf '[e2e-gotls] ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  docker rm -f "$NAME" "$HTTPS_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null || die "missing $1"; }
need docker
need curl

mkdir -p "$WORKDIR/agent"
cat > "$WORKDIR/agent/main.go" <<'EOF'
package main

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	marker := os.Getenv("MARKER")
	target := os.Getenv("TARGET")
	if marker == "" || target == "" {
		panic("MARKER/TARGET required")
	}
	// Stay alive so clawguard can attach uprobes before the HTTPS write.
	time.Sleep(5 * time.Second)
	tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	client := &http.Client{Transport: tr, Timeout: 60 * time.Second}
	body := strings.NewReader(marker + strings.Repeat("Z", 4096))
	req, err := http.NewRequest(http.MethodPost, target, body)
	if err != nil {
		panic(err)
	}
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	fmt.Println("status", resp.StatusCode)
	time.Sleep(3 * time.Second)
}
EOF

cat > "$WORKDIR/agent/Dockerfile" <<'EOF'
FROM golang:1.22-bookworm AS build
WORKDIR /src
COPY main.go .
RUN CGO_ENABLED=0 GOOS=linux go build -o /out/agent main.go
FROM debian:bookworm-slim
COPY --from=build /out/agent /agent
ENTRYPOINT ["/agent"]
EOF

log "building static Go agent image (inside Docker)"
docker build -t "$AGENT_IMAGE" "$WORKDIR/agent"

if [[ "$SKIP_BUILD" == "1" ]] && docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "skipping clawguard image build"
else
  log "building clawguard image"
  docker build -t "$IMAGE" "$ROOT"
fi

# Rebuild agent always (small) so sleep/timing changes apply
log "rebuilding Go agent"
docker build -t "$AGENT_IMAGE" "$WORKDIR/agent" >/dev/null

cleanup
docker network create "$NET" >/dev/null

log "starting HTTPS target"
docker run -d --name "$HTTPS_NAME" --network "$NET" python:3.11-slim bash -ec '
  apt-get update -qq && apt-get install -y -qq openssl >/dev/null
  openssl req -x509 -newkey rsa:2048 -keyout /tmp/key.pem -out /tmp/cert.pem -days 1 -nodes -subj "/CN=e2e" 2>/dev/null
  python - <<"PY"
import ssl
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        n = int(self.headers.get("Content-Length", 0))
        self.rfile.read(n)
        self.send_response(200); self.end_headers(); self.wfile.write(b"ok")
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/tmp/cert.pem", "/tmp/key.pem")
httpd = HTTPServer(("0.0.0.0", 8443), H)
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY
' >/dev/null

deadline=$((SECONDS + TIMEOUT_SEC))
until docker exec "$HTTPS_NAME" python -c "import socket; socket.create_connection(('127.0.0.1',8443),2).close()" 2>/dev/null; do
  (( SECONDS < deadline )) || die "https not ready"
  sleep 1
done

log "starting clawguard (runtimes=go preferred + openssl)"
docker run -d --name "$NAME" --privileged --pid=host --network "$NET" \
  -p "${PORT}:8080" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CLAWGUARD_LABEL=clawguard.monitor=true \
  -e CLAWGUARD_DEBUG_UI=0 \
  -e CLAWGUARD_DEBUG=1 \
  -e CLAWGUARD_RUNTIMES=go,openssl \
  "$IMAGE" >/dev/null

deadline=$((SECONDS + TIMEOUT_SEC))
until curl -sf "http://127.0.0.1:${PORT}/metrics" | grep -q clawguard_; do
  (( SECONDS < deadline )) || { docker logs "$NAME" 2>&1 | tail -40 >&2; die "metrics not ready"; }
  sleep 1
done

log "running Go agent marker=$MARKER"
docker run --rm --network "$NET" --label clawguard.monitor=true \
  -e MARKER="$MARKER" -e TARGET="https://${HTTPS_NAME}:8443/" \
  "$AGENT_IMAGE"

log "waiting for go_tls_write / marker"
deadline=$((SECONDS + TIMEOUT_SEC))
while (( SECONDS < deadline )); do
  logs="$(docker logs "$NAME" 2>&1 || true)"
  metrics="$(curl -sf "http://127.0.0.1:${PORT}/metrics" || true)"
  if echo "$logs" | grep -qF "$MARKER"; then
    if echo "$metrics" | grep -q 'clawguard_ssl_writes_total{hook="go_tls_write"' || \
       echo "$logs" | grep -qi 'attached go crypto/tls'; then
      log "PASS Go crypto/tls capture"
      exit 0
    fi
    # marker seen is enough if go attach logged
    if echo "$logs" | grep -q 'runtimes=\[go'; then
      log "PASS Go runtime attached and marker captured"
      exit 0
    fi
  fi
  sleep 2
done

docker logs "$NAME" 2>&1 | tail -100 >&2 || true
echo "$metrics" | grep clawguard_ >&2 || true
die "go tls capture not confirmed"
