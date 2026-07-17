package main

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var (
	metricSSLWrites = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "clawguard_ssl_writes_total",
		Help: "Total reassembled SSL_write / SSL_write_ex captures",
	}, []string{"hook", "truncated"})

	metricSSLWriteBytes = promauto.NewCounter(prometheus.CounterOpts{
		Name: "clawguard_ssl_write_bytes_total",
		Help: "Total captured plaintext bytes after reassembly",
	})

	metricReassemblyTimeouts = promauto.NewCounter(prometheus.CounterOpts{
		Name: "clawguard_reassembly_timeouts_total",
		Help: "Reassembly buffers discarded after TTL",
	})

	metricAttachedTargets = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "clawguard_attached_targets",
		Help: "Number of containers/pods currently attached with uprobes",
	})

	metricAttachErrors = promauto.NewCounter(prometheus.CounterOpts{
		Name: "clawguard_attach_errors_total",
		Help: "Failed attempts to discover libssl or attach uprobes",
	})

	metricChunkPoolExhausted = promauto.NewCounter(prometheus.CounterOpts{
		Name: "clawguard_chunk_pool_exhausted_total",
		Help: "Fragment drops because the userspace chunk pool had no free slab",
	})

	metricChunkPoolFree = promauto.NewGauge(prometheus.GaugeOpts{
		Name: "clawguard_chunk_pool_free",
		Help: "Approximate free chunk slots in the userspace pool",
	})

	metricFragmentDrops = promauto.NewCounter(prometheus.CounterOpts{
		Name: "clawguard_fragment_drops_total",
		Help: "Fragments dropped (invalid, empty, or pool exhausted)",
	})

	metricSinkDropped = promauto.NewCounterVec(prometheus.CounterOpts{
		Name: "clawguard_sink_dropped_total",
		Help: "Events dropped because a sink or async-processor queue was full (label may be processor:name)",
	}, []string{"plugin"})

	metricBuildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "clawguard_build_info",
		Help: "ClawGuard host build identity",
	}, []string{"version", "commit", "edition"})

	metricPluginInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Name: "clawguard_plugin_info",
		Help: "Loaded plugin identity",
	}, []string{"name", "kind", "version", "commit"})
)

func recordSinkDrop(plugin string) {
	metricSinkDropped.WithLabelValues(plugin).Inc()
}

func setBuildInfo(version, commit, edition string) {
	metricBuildInfo.Reset()
	metricBuildInfo.WithLabelValues(version, commit, edition).Set(1)
}

func setPluginInfoMetrics(name, kind, version, commit string) {
	metricPluginInfo.WithLabelValues(name, kind, version, commit).Set(1)
}

func resetPluginInfoMetrics() {
	metricPluginInfo.Reset()
}

func hookTypeLabel(hook uint32) string {
	switch hook {
	case 1:
		return "ssl_write"
	case 2:
		return "ssl_write_ex"
	case 3:
		return "go_tls_write"
	default:
		return "unknown"
	}
}

func recordSSLWrite(hook uint32, truncated bool, capturedBytes int) {
	metricSSLWrites.WithLabelValues(hookTypeLabel(hook), strconv.FormatBool(truncated)).Inc()
	if capturedBytes > 0 {
		metricSSLWriteBytes.Add(float64(capturedBytes))
	}
}

func setAttachedTargets(n int) {
	metricAttachedTargets.Set(float64(n))
}

func recordAttachError() {
	metricAttachErrors.Inc()
}

func recordReassemblyTimeout() {
	metricReassemblyTimeouts.Inc()
}

func recordChunkPoolExhausted() {
	metricChunkPoolExhausted.Inc()
}

func recordFragmentDrop() {
	metricFragmentDrops.Inc()
}

func setChunkPoolFree(n int) {
	metricChunkPoolFree.Set(float64(n))
}
