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

## 4. Web UI & Quick Start

ClawGuard features a built-in **Wireshark-inspired Web UI** for real-time monitoring and historical audit.

![ClawGuard UI](clawguard-ui.png)

### 4.1 Features
- **Real-time Streaming**: Capture and display TLS plaintext as it happens via WebSockets.
- **Deep Inspection**: Metadata view including Container ID, PID, TID, and eBPF hook details.
- **Hex Dump View**: Professional 16-column Hex + ASCII display for binary payloads.
- **Dark Mode**: Fully optimized dark theme for low-light environments.
- **Adjustable Layout**: Interactive splitters to resize the packet list, details, and hex view.
- **Export**: One-click JSON export for further analysis.

### 4.2 Run the Monitor with Web UI

1. **Pull** the image:
   ```bash
   docker pull eyelessly/clawguard:latest
   ```

2. **Run** the monitor with port mapping (8080):
   ```bash
   docker rm -f clawguard 2>/dev/null
   docker run -d --name clawguard \
     --privileged --pid=host \
     -p 8080:8080 \
     -v /var/run/docker.sock:/var/run/docker.sock \
     -e CLAWGUARD_LABEL=clawguard.monitor=true \
     eyelessly/clawguard:latest
   ```

3. **IMPORTANT: Label your Agents!**
   ClawGuard only captures traffic from containers that have the matching label. When starting your AI agent or any target container, you **must** add:
   ```bash
   docker run --label clawguard.monitor=true ...
   ```

4. **Access**: Open [http://localhost:8080](http://localhost:8080) in your browser.

---

## 5. Quick Verification

You can verify the system either through the **Web UI** or **CLI**.

### 5.1 Verify with a Test Agent (UI)

Once the monitor is running and you have opened the Web UI at `localhost:8080`, run this command to see live capture:

```bash
docker run --rm --label clawguard.monitor=true python:3.11-slim bash -ec '
  pip install -q requests
  python -c "import requests; requests.post(\"https://httpbin.org/post\", data=\"MY_SECRET_PASSWORD_123\")"
'
```
You should immediately see the `MY_SECRET_PASSWORD_123` payload appear in the ClawGuard Web UI.

### 5.2 Verify via CLI Only

If you prefer stdout, you can still verify the logs:

**Terminal A** — monitor with debug logging:
- A **ring buffer** carries plaintext **fragments** (fixed **512 bytes** per fragment, up to **16384 bytes** total per logical write in current build) to user space; the Go process reassembles and logs payloads.
- The monitor subscribes to Docker **start** / **die** / **destroy** and attaches/detaches accordingly; it skips itself via cgroup / hostname / API PID match.

**Runtime:** Linux kernel only (Docker Desktop VM or Linux host). Image arch must match the engine (**amd64** / **arm64**).

---

## 6. Advanced: build from source (developers)

Use this when you **modify code**, or when **no pre-built image** is available yet. End users should prefer **`docker pull`** (§4).

### 6.1 Docker image (macOS / Windows / Linux)

**You do not run `make build` on the host before this.** The `Dockerfile` already runs `make generate` and compiles the Go binary **inside** the build stage, so `docker build` (or `make docker-build` below) is enough.

```bash
git clone https://github.com/eyelesly/clawguard.git
cd clawguard

docker build -t clawguard:local .

# or load a single-arch image with buildx (--load requires one platform):
make docker-info
make docker-build IMAGE=clawguard:local
```

Override platform explicitly if needed: `make docker-build-amd64` or `make docker-build-arm64`. Then run with `clawguard:local` (or retag / push to your registry).

### 6.2 Linux host without Docker (native binary)

**Separate from §6.1** — for running `./bin/clawguard` on bare Linux, not for building the container image.

Requires `clang`, `llvm`, `libbpf-dev`, Go **1.22+**. The Makefile sets **BPF arch from `uname -m`** (`x86_64` / `aarch64` / `arm64`).

```bash
# Linux Only
make build
sudo ./bin/clawguard
```

---

## 7. Limitations

- **OpenSSL dynamic linking** only (`SSL_write` / `SSL_write_ex`). Not BoringSSL, not typical fully static Go `crypto/tls` without symbols.
- Reassembly is bounded: up to **16384 bytes** per logical write in current stage; larger writes are truncated.
- Reassembly timeout is short (2s): if fragments are dropped under heavy pressure, a timeout log is emitted and that payload is discarded.
- Truncation is explicit in logs with `truncated=true`, plus `orig_len` and `captured_len` for auditability.
