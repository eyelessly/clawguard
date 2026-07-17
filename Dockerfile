# Build must match the Linux kernel arch that loads the BPF program (Docker Desktop VM).
FROM node:20-slim AS frontend-builder
WORKDIR /ui
COPY ui/package*.json ./
RUN npm install
COPY ui/ ./
RUN npm run build

FROM golang:1.22-bookworm AS builder

ARG TARGETARCH
ARG VERSION=dev
ARG COMMIT=unknown
ARG BUILD_TIME=unknown
ARG EDITION=oss

RUN apt-get update -qq && apt-get install -y -qq clang llvm libbpf-dev && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY Makefile ./
COPY bpf/ bpf/
COPY cmd/ cmd/
COPY internal/ internal/
COPY api/ api/
COPY pkg/ pkg/

# bpf2go + DEB_ARCH + __TARGET_ARCH_* (see Makefile)
RUN case "$TARGETARCH" in \
	amd64)  export DEB_ARCH=x86_64-linux-gnu BPF_ARCH_FLAGS=-D__TARGET_ARCH_x86 ;; \
	arm64)  export DEB_ARCH=aarch64-linux-gnu BPF_ARCH_FLAGS=-D__TARGET_ARCH_arm64 ;; \
	*) echo "unsupported TARGETARCH=$TARGETARCH"; exit 1 ;; \
	esac && \
	LDFLAGS="-X clawguard/internal/version.Version=${VERSION} -X clawguard/internal/version.Commit=${COMMIT} -X clawguard/internal/version.BuildTime=${BUILD_TIME} -X clawguard/internal/version.Edition=${EDITION}" && \
	make generate && \
	CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/clawguard ./cmd/clawguard && \
	CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/clawguard-sink-file ./cmd/clawguard-sink-file && \
	CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/clawguard-sink-otel ./cmd/clawguard-sink-otel && \
	CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/clawguard-sink-debugws ./cmd/clawguard-sink-debugws && \
	CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/clawguard-processor-detect ./cmd/clawguard-processor-detect && \
	CGO_ENABLED=0 go build -ldflags "$LDFLAGS" -o /out/clawguard-processor-mask ./cmd/clawguard-processor-mask

FROM debian:bookworm-slim
RUN apt-get update -qq && apt-get install -y -qq ca-certificates && rm -rf /var/lib/apt/lists/* \
	&& mkdir -p /var/lib/clawguard/plugins /var/log/clawguard /etc/clawguard
COPY --from=builder /out/clawguard /usr/local/bin/clawguard
COPY --from=builder /out/clawguard-sink-file /var/lib/clawguard/plugins/clawguard-sink-file
COPY --from=builder /out/clawguard-sink-otel /var/lib/clawguard/plugins/clawguard-sink-otel
COPY --from=builder /out/clawguard-sink-debugws /var/lib/clawguard/plugins/clawguard-sink-debugws
COPY --from=builder /out/clawguard-processor-detect /var/lib/clawguard/plugins/clawguard-processor-detect
COPY --from=builder /out/clawguard-processor-mask /var/lib/clawguard/plugins/clawguard-processor-mask
COPY --from=frontend-builder /ui/dist /ui/dist
COPY deploy/config/config.yaml /etc/clawguard/config.yaml
WORKDIR /
ENV CLAWGUARD_CONFIG=/etc/clawguard/config.yaml
ENV CLAWGUARD_PLUGIN_DIR=/var/lib/clawguard/plugins
ENTRYPOINT ["/usr/local/bin/clawguard"]
