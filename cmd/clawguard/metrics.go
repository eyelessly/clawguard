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
)

func hookTypeLabel(hook uint32) string {
	switch hook {
	case 1:
		return "ssl_write"
	case 2:
		return "ssl_write_ex"
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
