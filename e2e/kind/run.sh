#!/usr/bin/env bash
# ClawGuard kind E2E: kind cluster → load image → DaemonSet → annotated Pod → metrics.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
CLUSTER="${CLAWGUARD_KIND_CLUSTER:-clawguard-e2e}"
IMAGE="${CLAWGUARD_IMAGE:-clawguard:e2e}"
MARKER="${CLAWGUARD_MARKER:-CLAWGUARD_KIND_SECRET_$(date +%s)}"
TIMEOUT_SEC="${CLAWGUARD_E2E_TIMEOUT:-180}"
KEEP="${CLAWGUARD_KIND_KEEP:-0}"

log() { printf '[e2e-kind] %s\n' "$*"; }
die() { printf '[e2e-kind] ERROR: %s\n' "$*" >&2; exit 1; }

cleanup() {
  if [[ "$KEEP" == "1" ]]; then
    log "KEEP=1 — leaving cluster $CLUSTER"
    return
  fi
  kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

need() { command -v "$1" >/dev/null || die "missing dependency: $1"; }
need docker
need kind
need kubectl

log "building image $IMAGE"
docker build -t "$IMAGE" "$ROOT"

if ! kind get clusters 2>/dev/null | grep -qx "$CLUSTER"; then
  log "creating kind cluster $CLUSTER"
  kind create cluster --name "$CLUSTER"
else
  log "reusing kind cluster $CLUSTER"
fi

log "loading image into kind"
kind load docker-image "$IMAGE" --name "$CLUSTER"

# Patch DaemonSet to use local image + Never pull
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"; cleanup' EXIT
cp "$ROOT/deploy/kubernetes/"*.yaml "$tmp/"
# shellcheck disable=SC2016
sed -i.bak \
  -e "s|image: eyelessly/clawguard:latest|image: ${IMAGE}|" \
  -e "s|imagePullPolicy: IfNotPresent|imagePullPolicy: Never|" \
  "$tmp/daemonset.yaml"

log "applying RBAC + DaemonSet"
kubectl apply -f "$tmp/rbac.yaml"
kubectl apply -f "$tmp/daemonset.yaml"

log "waiting for DaemonSet ready"
kubectl -n clawguard rollout status ds/clawguard --timeout="${TIMEOUT_SEC}s"

# Demo pod with unique marker
cat > "$tmp/demo.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: clawguard-e2e-agent
  namespace: default
  annotations:
    clawguard.io/monitor: "true"
spec:
  restartPolicy: Never
  containers:
    - name: agent
      image: python:3.11-slim
      command:
        - bash
        - -ec
        - |
          pip install -q requests
          python -c "import requests; requests.post('https://httpbin.org/post', data='${MARKER}', headers={'traceparent':'00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01'}, timeout=30)"
          sleep 30
EOF

kubectl delete pod clawguard-e2e-agent -n default --ignore-not-found >/dev/null 2>&1 || true
kubectl apply -f "$tmp/demo.yaml"
kubectl wait --for=condition=Ready pod/clawguard-e2e-agent -n default --timeout="${TIMEOUT_SEC}s" || true

log "port-forward metrics and assert"
kubectl -n clawguard port-forward svc/clawguard 18081:8080 >/tmp/clawguard-pf.log 2>&1 &
pf=$!
sleep 2

deadline=$((SECONDS + TIMEOUT_SEC))
found_metric=0
found_log=0
while (( SECONDS < deadline )); do
  if curl -sf http://127.0.0.1:18081/metrics 2>/dev/null | awk '/^clawguard_ssl_writes_total/{s+=$2} END{exit !(s>0)}'; then
    found_metric=1
  fi
  if kubectl -n clawguard logs -l app.kubernetes.io/name=clawguard --tail=200 2>/dev/null | grep -qF "$MARKER"; then
    found_log=1
  fi
  if (( found_metric == 1 && found_log == 1 )); then
    kill "$pf" 2>/dev/null || true
    log "PASS kind: ssl_writes>0 and marker in DaemonSet logs"
    exit 0
  fi
  sleep 2
done

kill "$pf" 2>/dev/null || true
kubectl -n clawguard get pods -o wide >&2 || true
kubectl -n clawguard logs -l app.kubernetes.io/name=clawguard --tail=100 >&2 || true
die "timeout: metric_ok=$found_metric log_ok=$found_log"
