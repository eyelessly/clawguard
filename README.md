# ClawGuard

![ClawGuard](clawguard-logo.png)

Monitor **TLS plaintext that your agents are about to send**—from outside the agent image—so you can audit secrets and policy before they hit the wire. This repo ships a **Docker-ready** eBPF collector (`clawguard`).

---

## 1. What ClawGuard does

### Why we call out specific AI agents (privacy risk)

[**OpenClaw**](https://openclaw.ai/), [**nanobot**](https://github.com/HKUDS/nanobot), and similar **autonomous AI agent** stacks are often run in containers with tool use, API keys, and access to user or environment context. In practice, that means **real risk of leaking personal information, prompts, or credentials** over **HTTPS**—whether through misconfiguration, overly broad tools, or unexpected model behavior. ClawGuard does not replace secure design or policy, but it gives **operators** a way to **see what plaintext is about to be written to TLS** (for workloads using dynamic **OpenSSL**), so you can **audit, alert, and respond** before data leaves your boundary.

- **Observes HTTPS writes at the OpenSSL layer** (`SSL_write` / `SSL_write_ex`) inside **Docker containers** you care about (typically **AI/agents** using `Python`, `node`, `curl`, etc. with dynamic `libssl`).
- **Shows bytes before encryption**: useful to catch accidental **PII**, **API tokens**, or other sensitive payloads in outbound requests.
- **Targets containers you select** via Docker **labels** (recommended) or, without a filter, any other container on the same Docker engine (use labels in production).

**What it is not:** a tool for monitoring a person’s normal desktop browsing. It is aimed at **operator-controlled agent workloads** you run in containers.

---

## 2. Why it is safe (for your security model)

- **No TLS MITM in the network path**—traffic does not go through a decrypting proxy; the agent still speaks real TLS to the remote server.
- **No extra CA or proxy config inside the agent image**—you are not weakening TLS trust for the workload.
- **Scope is container- and label-based**: you attach visibility only to workloads you label (or explicitly allow), and the monitor skips its own container.
- **Audit-friendly**: events go to **stdout**; you can ship logs to your existing stack.

Running the monitor still requires **elevated privileges** on the Linux host/VM (`--privileged`, eBPF)—that is expected for kernel tracing; scope it to ops-managed machines.

---

## 3. Why it is painless (non-intrusive)

- **No change to agent source code or Dockerfiles** for the agent itself.
- **No certificate injection** into the agent container.
- **Kernel eBPF uprobes** on `libssl` in the agent’s filesystem view: the same buffers the app passes to OpenSSL are observed **before** encryption.
- **Opt-in with labels**: add `--label` to agent containers and (optionally) `CLAWGUARD_LABEL` on the monitor—fits normal Docker Compose / orchestration habits.

---

## 4. Quick start and quick verification

**Prerequisites:** [Docker](https://docs.docker.com/get-docker/) running (on macOS/Windows use **Docker Desktop**; eBPF runs in the Linux VM).

**Recommended path:** pull a **pre-built multi-arch image** (no `git clone`, no local build). CI publishes to **Docker Hub** and/or **GHCR**—use whichever your project documents after release.

### 4.1 Pull and run the monitor

1. **Choose the image** (replace placeholders with your org/user; tags may be `latest`, `main`, or a version):

   ```bash
   # Docker Hub (typical)
   export CLAWGUARD_IMAGE=docker.io/YOUR_DOCKERHUB_USER/clawguard:latest

   # Or GitHub Container Registry
   # export CLAWGUARD_IMAGE=ghcr.io/your-org/clawguard:main
   ```

2. **Pull** (Docker selects **amd64** or **arm64** to match your engine when the manifest is multi-arch):

   ```bash
   docker pull "$CLAWGUARD_IMAGE"
   ```

3. **Run** the monitor:

   ```bash
   docker rm -f clawguard-manager 2>/dev/null
   docker run -d --name clawguard-manager \
     --privileged --pid=host --net=host \
     -v /var/run/docker.sock:/var/run/docker.sock \
     "$CLAWGUARD_IMAGE"
   docker logs -f clawguard-manager
   ```

You should see **`BPF collection loaded OK`** and **`ClawGuard: listening`**. **Ctrl+C** stops following logs; use `docker logs -f clawguard-manager` again anytime.

### 4.2 Verify in ~30 seconds (labeled agent)

**Terminal A** — monitor **only** containers with `clawguard.monitor=true` (reuse the same `CLAWGUARD_IMAGE`):

```bash
docker rm -f clawguard-manager
docker run -d --name clawguard-manager \
  --privileged --pid=host --net=host \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e CLAWGUARD_LABEL=clawguard.monitor=true \
  -e CLAWGUARD_DEBUG=1 \
  "$CLAWGUARD_IMAGE"
docker logs -f clawguard-manager
```

**Terminal B** — run a one-off “agent” with the same label:

```bash
docker run --rm --label clawguard.monitor=true python:3.11-slim bash -ec '
  pip install -q requests
  python -c "import requests; requests.post(\"https://httpbin.org/post\", data=\"MY_SECRET_PASSWORD_123\")"
'
```

In **Terminal A** you should see log lines with `payload=` containing `MY_SECRET_PASSWORD_123` (possibly among other TLS writes). When done: **Ctrl+C**, then `docker rm -f clawguard-manager`.

### 4.3 No published image yet?

Build the image locally once, then use your local tag everywhere instead of `CLAWGUARD_IMAGE` (see **§6.1**). You need a **git clone** of this repo only for that path.

### 4.4 Fit into *your* Docker setup

- **Same Docker host** as your agents: mount `/var/run/docker.sock` (as above). The monitor discovers containers via the API.
- **Label your agent services** in Compose/Kubernetes-on-Docker the same way: `labels: ["clawguard.monitor=true"]` (or your own key/value) and set **`CLAWGUARD_LABEL`** on the monitor to match.
- **Use `--pid=host`** on the monitor so `/proc` PIDs match Docker’s view (required for reliable attach on many setups).

---

## 5. How it works (mechanism, short)

- eBPF programs attach **uprobes** to the agent container’s `libssl.so` for **`SSL_write`** and **`SSL_write_ex`** (Python 3.10+ uses `_ex`).
- A **ring buffer** carries small plaintext slices (cap **256 bytes** per event) to user space; the Go process logs them.
- The monitor subscribes to Docker **start** / **die** / **destroy** and attaches/detaches accordingly; it skips itself via cgroup / hostname / API PID match.

**Runtime:** Linux kernel only (Docker Desktop VM or Linux host). Image arch must match the engine (**amd64** / **arm64**).

---

## 6. Advanced: build from source (developers)

Use this when you **modify code**, or when **no pre-built image** is available yet. End users should prefer **`docker pull`** (§4).

### 6.1 Docker image (macOS / Windows / Linux)

**You do not run `make build` on the host before this.** The `Dockerfile` already runs `make generate` and compiles the Go binary **inside** the build stage, so `docker build` (or `make docker-build` below) is enough.

```bash
git clone https://github.com/YOUR_ORG/clawguard.git
cd clawguard

docker build -t clawguard-https-demo .
# or load a single-arch image with buildx (--load requires one platform):
make docker-info
make docker-build IMAGE=clawguard-https-demo
```

Override platform explicitly if needed: `make docker-build-amd64` or `make docker-build-arm64`. Then run with `clawguard-https-demo` (or retag / push to your registry).

### 6.2 Linux host without Docker (native binary)

**Separate from §6.1** — for running `./bin/clawguard` on bare Linux, not for building the container image.

Requires `clang`, `llvm`, `libbpf-dev`, Go **1.22+**. The Makefile sets **BPF arch from `uname -m`** (`x86_64` / `aarch64` / `arm64`).

```bash
make build
sudo ./bin/clawguard
```

### 6.3 Where pre-built images come from

CI builds multi-arch images and pushes to **GHCR** and (if you set secrets) **Docker Hub**—same **`docker pull`** flow as **§4.1**. Optional repository secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`.

### 6.4 CI/CD (this repo)

- **`.github/workflows/docker-publish.yml`** — multi-arch image; push on `main` / tags; PRs build only.
- **`.github/workflows/release-binaries.yml`** — on `v*` tags, native Linux **amd64** / **arm64** tarballs (public repos: `ubuntu-24.04-arm` for arm64).

When this folder is the **Git root**, `.github/workflows/` is at the repo root.

---

## 7. Limitations

- **OpenSSL dynamic linking** only (`SSL_write` / `SSL_write_ex`). Not BoringSSL, not typical fully static Go `crypto/tls` without symbols.
- **256-byte** cap per captured chunk in BPF; longer bodies appear truncated in the log (length may still be reported up to that cap).
