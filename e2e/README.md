# ClawGuard E2E

All Go/BPF compilation happens **inside `docker build`** (never on the host).

## Suites

| Suite | Script | What it proves |
|-------|--------|----------------|
| OpenSSL smoke | [`docker/run.sh`](docker/run.sh) | metrics + marker in logs **and** versioned file sink JSONL |
| Large payload | [`docker/run_large.sh`](docker/run_large.sh) | ≥2MiB full capture in **host** `e2e/out/large/plaintext.jsonl` |
| Go crypto/tls | [`docker/run_go_tls.sh`](docker/run_go_tls.sh) | static Go agent → `go_tls_write` |
| kind | [`kind/run.sh`](kind/run.sh) | DaemonSet + annotation |
| OTel | [`otel/run.sh`](otel/run.sh) | OTLP via `clawguard-sink-otel` plugin |

```bash
chmod +x e2e/docker/*.sh e2e/kind/run.sh e2e/otel/run.sh
./e2e/docker/run.sh
CLAWGUARD_SKIP_BUILD=1 ./e2e/docker/run_large.sh
CLAWGUARD_SKIP_BUILD=1 ./e2e/docker/run_go_tls.sh
```

CI: [`.github/workflows/e2e-docker.yml`](../.github/workflows/e2e-docker.yml) runs the OpenSSL smoke suite.
