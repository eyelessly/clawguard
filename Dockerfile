# Build must match the Linux kernel arch that loads the BPF program (Docker Desktop VM).
FROM node:20-slim AS frontend-builder
WORKDIR /ui
COPY ui/package*.json ./
RUN npm install
COPY ui/ ./
RUN npm run build

FROM golang:1.22-bookworm AS builder

ARG TARGETARCH
RUN apt-get update -qq && apt-get install -y -qq clang llvm libbpf-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY Makefile ./
COPY bpf/ bpf/
COPY cmd/ cmd/

# bpf2go + DEB_ARCH + __TARGET_ARCH_* (see Makefile)
RUN case "$TARGETARCH" in \
	amd64)  export DEB_ARCH=x86_64-linux-gnu BPF_ARCH_FLAGS=-D__TARGET_ARCH_x86 ;; \
	arm64)  export DEB_ARCH=aarch64-linux-gnu BPF_ARCH_FLAGS=-D__TARGET_ARCH_arm64 ;; \
	*) echo "unsupported TARGETARCH=$TARGETARCH"; exit 1 ;; \
	esac && \
	make generate && \
	CGO_ENABLED=0 go build -o /out/clawguard ./cmd/clawguard

FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /out/clawguard /usr/local/bin/clawguard
COPY --from=frontend-builder /ui/dist /ui/dist
WORKDIR /
ENTRYPOINT ["/usr/local/bin/clawguard"]
