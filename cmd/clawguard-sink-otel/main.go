package main

import (
	"context"
	"encoding/hex"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	pluginv1 "clawguard/api/plugin/v1"
	"clawguard/internal/event"
	"clawguard/internal/version"
	"clawguard/pkg/pluginsdk"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
)

var traceparentRe = regexp.MustCompile(`(?i)(?:^|\r?\n)traceparent:\s*([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})`)

func main() {
	pluginsdk.MaybeVersionFlag("clawguard-sink-otel")
	pluginsdk.Serve(&otelSink{})
}

type otelSink struct {
	pluginsdk.SinkOnly
	logger   otellog.Logger
	provider *sdklog.LoggerProvider
	preview  int
}

func (s *otelSink) Info() pluginv1.PluginInfo {
	return pluginsdk.FillInfo("otel", "sink")
}

func (s *otelSink) Configure(cfg pluginv1.PluginConfig) error {
	endpoint, _ := cfg.Settings["endpoint"].(string)
	if endpoint == "" {
		endpoint = strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	}
	if endpoint == "" {
		return nil // no-op sink
	}
	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" {
		_ = os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
	}
	serviceName, _ := cfg.Settings["service_name"].(string)
	if serviceName == "" {
		serviceName = os.Getenv("OTEL_SERVICE_NAME")
	}
	if serviceName == "" {
		serviceName = "clawguard"
	}
	s.preview = 16384

	opts := []otlploghttp.Option{}
	insecure, _ := cfg.Settings["insecure"].(bool)
	if insecure || strings.HasPrefix(endpoint, "http://") || os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "1" {
		opts = append(opts, otlploghttp.WithInsecure())
	}
	exporter, err := otlploghttp.New(context.Background(), opts...)
	if err != nil {
		return err
	}
	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
			semconv.ServiceVersion(version.Version),
		),
	)
	if err != nil {
		return err
	}
	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)
	s.provider = provider
	s.logger = provider.Logger("clawguard.ssl_write")
	log.Printf("otel sink → %s service=%s", endpoint, serviceName)
	return nil
}

func (s *otelSink) Emit(ev *event.CaptureEvent) error {
	if s.logger == nil {
		return nil
	}
	body := string(ev.Payload)
	if len(body) > s.preview {
		body = body[:s.preview] + "…"
	}
	attrs := []otellog.KeyValue{
		otellog.Int64("pid", int64(ev.PID)),
		otellog.Int64("tid", int64(ev.TID)),
		otellog.Int64("call_id", int64(ev.CallID)),
		otellog.Int64("orig_len", int64(ev.OrigLen)),
		otellog.Int64("captured_len", int64(ev.CapturedLen)),
		otellog.Bool("truncated", ev.Truncated),
		otellog.String("clawguard.version", ev.ClawguardVersion),
		otellog.String("clawguard.commit", ev.ClawguardCommit),
		otellog.String("container.id", ev.ContainerID),
	}
	if ev.PodName != "" {
		attrs = append(attrs, otellog.String("k8s.pod.name", ev.PodName))
	}
	if ev.PodNamespace != "" {
		attrs = append(attrs, otellog.String("k8s.namespace.name", ev.PodNamespace))
	}

	var record otellog.Record
	record.SetTimestamp(ev.Timestamp)
	record.SetObservedTimestamp(time.Now())
	record.SetBody(otellog.StringValue(body))
	record.SetSeverity(otellog.SeverityInfo)
	record.AddAttributes(attrs...)

	emitCtx := context.Background()
	if tid, sid, ok := parseTraceparent(string(ev.Payload)); ok {
		record.AddAttributes(
			otellog.String("trace_id", tid.String()),
			otellog.String("span_id", sid.String()),
		)
		sc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled, Remote: true,
		})
		emitCtx = trace.ContextWithSpanContext(context.Background(), sc)
	}
	s.logger.Emit(emitCtx, record)
	return nil
}

func (s *otelSink) Close() error {
	if s.provider != nil {
		return s.provider.Shutdown(context.Background())
	}
	return nil
}

func parseTraceparent(payload string) (trace.TraceID, trace.SpanID, bool) {
	m := traceparentRe.FindStringSubmatch(payload)
	if len(m) < 4 {
		return trace.TraceID{}, trace.SpanID{}, false
	}
	traceBytes, err := hex.DecodeString(m[2])
	if err != nil || len(traceBytes) != 16 {
		return trace.TraceID{}, trace.SpanID{}, false
	}
	spanBytes, err := hex.DecodeString(m[3])
	if err != nil || len(spanBytes) != 8 {
		return trace.TraceID{}, trace.SpanID{}, false
	}
	var tid trace.TraceID
	var sid trace.SpanID
	copy(tid[:], traceBytes)
	copy(sid[:], spanBytes)
	return tid, sid, true
}
