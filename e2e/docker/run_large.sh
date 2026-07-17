#!/usr/bin/env bash
# Large-payload E2E: ≥2MiB POST; assert full plaintext in file sink on the host.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
IMAGE="${CLAWGUARD_IMAGE:-clawguard:e2e}"
NAME="${CLAWGUARD_NAME:-clawguard-e2e-large}"
HTTPS_NAME="${CLAWGUARD_HTTPS_NAME:-clawguard-e2e-https-large}"
NET="${CLAWGUARD_E2E_NET:-clawguard-e2e-large-net}"
PORT="${CLAWGUARD_PORT:-18083}"
TIMEOUT_SEC="${CLAWGUARD_E2E_TIMEOUT:-180}"
SKIP_BUILD="${CLAWGUARD_SKIP_BUILD:-0}"
SIZE_MB="${CLAWGUARD_LARGE_MB:-2}"
MARKER="CLAWGUARD_LARGE_$(date +%s)"
OUT_DIR="${CLAWGUARD_E2E_OUT:-$ROOT/e2e/out/large}"
OUT_JSONL="$OUT_DIR/plaintext.jsonl"

log() { printf '[e2e-large] %s\n' "$*"; }
die() { printf '[e2e-large] ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  docker rm -f "$NAME" "$HTTPS_NAME" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null || die "missing $1"; }
need docker
need curl
need python3

if [[ "$SKIP_BUILD" == "1" ]] && docker image inspect "$IMAGE" >/dev/null 2>&1; then
  log "skipping docker build"
else
  log "building image $IMAGE (compile inside Docker)"
  docker build -t "$IMAGE" "$ROOT"
fi

cleanup
docker network create "$NET" >/dev/null

mkdir -p "$OUT_DIR"
rm -f "$OUT_JSONL"

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

log "starting clawguard (file sink mounted to host: $OUT_JSONL)"
docker run -d --name "$NAME" --privileged --pid=host --network "$NET" \
  -p "${PORT}:8080" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$OUT_DIR:/var/log/clawguard" \
  -e CLAWGUARD_LABEL=clawguard.monitor=true \
  -e CLAWGUARD_DEBUG_UI=0 \
  -e CLAWGUARD_DEBUG=1 \
  -e CLAWGUARD_CHUNK_POOL_MB=512 \
  -e CLAWGUARD_REASSEMBLY_TTL=60s \
  -e CLAWGUARD_PAYLOAD_PREVIEW_MAX=128 \
  "$IMAGE" >/dev/null

deadline=$((SECONDS + TIMEOUT_SEC))
until curl -sf "http://127.0.0.1:${PORT}/metrics" | grep -q clawguard_; do
  (( SECONDS < deadline )) || { docker logs "$NAME" 2>&1 | tail -40 >&2; die "metrics not ready"; }
  sleep 1
done

BYTES=$((SIZE_MB * 1024 * 1024))
log "agent POST ${SIZE_MB}MiB marker=$MARKER"
docker run --rm --network "$NET" --label clawguard.monitor=true \
  -e MARKER="$MARKER" -e BYTES="$BYTES" -e TARGET="https://${HTTPS_NAME}:8443/" \
  python:3.11-slim bash -ec '
  pip install -q requests urllib3
  python - <<PY
import os, requests, urllib3
urllib3.disable_warnings()
marker = os.environ["MARKER"].encode()
n = int(os.environ["BYTES"])
pad = n - len(marker)
body = marker + (b"Y" * pad)
requests.post(os.environ["TARGET"], data=body, verify=False, timeout=120)
print("sent", len(body))
PY
'

log "waiting for full capture in logs + host file sink (expect body ${BYTES} bytes)"
deadline=$((SECONDS + TIMEOUT_SEC))
while (( SECONDS < deadline )); do
  logs="$(docker logs "$NAME" 2>&1 || true)"
  log_ok=0
  if echo "$logs" | grep -F "reassembled_len=${BYTES}" | grep -F "orig_len=${BYTES}" | grep -q "truncated=false"; then
    if echo "$logs" | grep -qF "$MARKER"; then
      log_ok=1
    fi
  fi

  file_ok=0
  if [[ -f "$OUT_JSONL" ]]; then
    if BYTES="$BYTES" MARKER="$MARKER" OUT_JSONL="$OUT_JSONL" python3 - <<'PY'
import base64, json, os, sys

path = os.environ["OUT_JSONL"]
want = int(os.environ["BYTES"])
marker = os.environ["MARKER"]
body = marker + ("Y" * (want - len(marker)))
best = None

with open(path) as f:
    for line in f:
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("type") == "session":
            continue

        text = row.get("payload_text") or ""
        if marker not in text:
            payload = row.get("payload")
            if isinstance(payload, str):
                try:
                    text = base64.b64decode(payload).decode("utf-8", "replace")
                except Exception:
                    continue
        if marker not in text:
            continue
        if bool(row.get("truncated")):
            continue
        captured = int(row.get("captured_len") or 0)
        if captured < want:
            continue
        if body not in text and not (
            len(text) >= want
            and text.startswith(marker)
            and text[len(marker) : want] == "Y" * (want - len(marker))
        ):
            continue
        best = row
        break

if not best:
    sys.exit(2)

text = best.get("payload_text") or ""
if marker not in text:
    text = base64.b64decode(best["payload"]).decode("utf-8", "replace")
assert body in text or text[:want] == body, "body not contiguous/complete in payload_text"
plugins = best.get("plugins") or []
print(
    f"file_ok captured_len={best.get('captured_len')} payload_text_len={len(text)} "
    f"truncated={best.get('truncated')} clawguard_version={best.get('clawguard_version')} "
    f"plugin_names={[p.get('name') for p in plugins]}"
)
sys.exit(0)
PY
    then
      file_ok=1
    fi
  fi

  if (( log_ok == 1 && file_ok == 1 )); then
    log "PASS full ${SIZE_MB}MiB capture"
    log "plaintext file kept at: $OUT_JSONL"
    ls -lh "$OUT_JSONL"
    exit 0
  fi
  sleep 2
done

docker logs "$NAME" 2>&1 | tail -100 >&2 || true
ls -la "$OUT_DIR" >&2 || true
curl -sf "http://127.0.0.1:${PORT}/metrics" | grep clawguard_ >&2 || true
die "large capture not confirmed in logs+file"
