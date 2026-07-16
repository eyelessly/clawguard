package main

import (
	"context"
	"encoding/hex"
	"log"
	"os"
	"regexp"
	"strings"
	"time"

	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
	semconv "go.opentelemetry.io/otel/semconv/v1.27.0"
	"go.opentelemetry.io/otel/trace"
)

var traceparentRe = regexp.MustCompile(`(?i)(?:^|\r?\n)traceparent:\s*([0-9a-f]{2})-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})`)

type otelEmitter struct {
	logger   otellog.Logger
	provider *sdklog.LoggerProvider
}

func initOTel(ctx context.Context) (*otelEmitter, error) {
	endpoint := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT"))
	if endpoint == "" {
		return nil, nil
	}

	serviceName := strings.TrimSpace(os.Getenv("OTEL_SERVICE_NAME"))
	if serviceName == "" {
		serviceName = "clawguard"
	}

	opts := []otlploghttp.Option{}
	if strings.HasPrefix(endpoint, "http://") || os.Getenv("OTEL_EXPORTER_OTLP_INSECURE") == "1" {
		opts = append(opts, otlploghttp.WithInsecure())
	}

	exporter, err := otlploghttp.New(ctx, opts...)
	if err != nil {
		return nil, err
	}

	res, err := resource.Merge(
		resource.Default(),
		resource.NewWithAttributes(
			semconv.SchemaURL,
			semconv.ServiceName(serviceName),
		),
	)
	if err != nil {
		return nil, err
	}

	provider := sdklog.NewLoggerProvider(
		sdklog.WithProcessor(sdklog.NewBatchProcessor(exporter)),
		sdklog.WithResource(res),
	)
	logger := provider.Logger("clawguard.ssl_write")
	log.Printf("OTel logs enabled → %s (service=%s)", endpoint, serviceName)
	return &otelEmitter{logger: logger, provider: provider}, nil
}

func (e *otelEmitter) shutdown(ctx context.Context) {
	if e == nil || e.provider == nil {
		return
	}
	if err := e.provider.Shutdown(ctx); err != nil {
		log.Printf("otel shutdown: %v", err)
	}
}

func (e *otelEmitter) emitSSLWrite(ev PacketEvent, payloadPreview string) {
	if e == nil {
		return
	}

	attrs := []otellog.KeyValue{
		otellog.Int64("pid", int64(ev.PID)),
		otellog.Int64("tid", int64(ev.TID)),
		otellog.Int64("call_id", int64(ev.CallID)),
		otellog.Int64("orig_len", int64(ev.OrigLen)),
		otellog.Int64("captured_len", int64(ev.CapturedLen)),
		otellog.Bool("truncated", ev.Truncated),
		otellog.String("hook", hookTypeLabel(ev.HookType)),
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
	record.SetBody(otellog.StringValue(payloadPreview))
	record.SetSeverity(otellog.SeverityInfo)
	record.SetSeverityText("INFO")
	record.AddAttributes(attrs...)

	emitCtx := context.Background()
	if tid, sid, ok := parseTraceparent(ev.Payload); ok {
		record.AddAttributes(
			otellog.String("trace_id", tid.String()),
			otellog.String("span_id", sid.String()),
		)
		sc := trace.NewSpanContext(trace.SpanContextConfig{
			TraceID:    tid,
			SpanID:     sid,
			TraceFlags: trace.FlagsSampled,
			Remote:     true,
		})
		emitCtx = trace.ContextWithSpanContext(context.Background(), sc)
	}

	e.logger.Emit(emitCtx, record)
}

// parseTraceparent extracts W3C traceparent from HTTP plaintext headers (best-effort).
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
