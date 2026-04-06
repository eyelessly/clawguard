# BPF + Go build. bpf2go runs on Linux (e.g. Docker build); on macOS use `docker build`.

BPF2GO := go run github.com/cilium/ebpf/cmd/bpf2go@v0.16.0
CLANG ?= clang
ARCH ?= $(shell uname -m)
ifeq ($(ARCH),x86_64)
  DEB_ARCH := x86_64-linux-gnu
  DOCKER_PLATFORM := linux/amd64
endif
ifeq ($(ARCH),aarch64)
  DEB_ARCH := aarch64-linux-gnu
  DOCKER_PLATFORM := linux/arm64
endif
ifeq ($(ARCH),arm64)
  DEB_ARCH := aarch64-linux-gnu
  DOCKER_PLATFORM := linux/arm64
endif
ifndef DEB_ARCH
  DEB_ARCH := x86_64-linux-gnu
endif
ifndef DOCKER_PLATFORM
  DOCKER_PLATFORM := linux/amd64
endif

# PT_REGS_PARM* in libbpf headers need an arch when -target bpf
ifeq ($(DEB_ARCH),aarch64-linux-gnu)
  BPF_ARCH_FLAGS := -D__TARGET_ARCH_arm64
endif
ifeq ($(DEB_ARCH),x86_64-linux-gnu)
  BPF_ARCH_FLAGS := -D__TARGET_ARCH_x86
endif
ifndef BPF_ARCH_FLAGS
  BPF_ARCH_FLAGS := -D__TARGET_ARCH_arm64
endif

# Local image: PLATFORM defaults from uname -m → linux/amd64 or linux/arm64 (override if needed).
IMAGE ?= clawguard:local
PLATFORM ?= $(DOCKER_PLATFORM)

.PHONY: generate build clean docker-build docker-build-amd64 docker-build-arm64 docker-info

# Little-endian BPF (amd64 + arm64). Set TARGET_BPF=bpfeb on big-endian hosts if needed.
TARGET_BPF ?= bpfel

generate:
	cd cmd/clawguard && $(BPF2GO) -go-package main -cc $(CLANG) -no-strip -target $(TARGET_BPF) ssl_write ../../bpf/ssl_write.bpf.c -- \
		-I/usr/include/$(DEB_ARCH) -I/usr/include $(BPF_ARCH_FLAGS)

build: generate
	mkdir -p bin
	CGO_ENABLED=0 go build -o bin/clawguard ./cmd/clawguard

clean:
	rm -f cmd/clawguard/ssl_write_bpfel.go cmd/clawguard/ssl_write_bpfeb.go
	rm -f cmd/clawguard/ssl_write_bpfel.o cmd/clawguard/ssl_write_bpfeb.o
	rm -f bin/clawguard

docker-build:
	docker buildx build --load --platform $(PLATFORM) -t $(IMAGE) .

docker-build-amd64:
	$(MAKE) docker-build PLATFORM=linux/amd64

docker-build-arm64:
	$(MAKE) docker-build PLATFORM=linux/arm64

docker-info:
	@echo "ARCH=$(ARCH) DEB_ARCH=$(DEB_ARCH) DOCKER_PLATFORM=$(DOCKER_PLATFORM) PLATFORM=$(PLATFORM) IMAGE=$(IMAGE)"
