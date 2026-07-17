package main

import (
	"regexp"

	pluginv1 "clawguard/api/plugin/v1"
	"clawguard/internal/event"
	"clawguard/pkg/pluginsdk"
)

// Builtin patterns so sync mask works without a preceding sync detect.
var apiKeyLike = regexp.MustCompile(`(?i)(sk-[a-z0-9]{16,}|api[_-]?key["\s:=]+[a-z0-9_\-]{8,})`)

func main() {
	pluginsdk.MaybeVersionFlag("clawguard-processor-mask")
	pluginsdk.Serve(&maskProc{})
}

type maskProc struct {
	pluginsdk.ProcessorOnly
}

func (m *maskProc) Info() pluginv1.PluginInfo {
	return pluginsdk.FillInfo("mask", "processor")
}

func (m *maskProc) Configure(pluginv1.PluginConfig) error { return nil }

func (m *maskProc) Process(ev *event.CaptureEvent) (*event.CaptureEvent, error) {
	if ev == nil {
		return ev, nil
	}
	findings := ev.Findings
	if len(findings) == 0 {
		for _, loc := range apiKeyLike.FindAllIndex(ev.Payload, -1) {
			findings = append(findings, event.Finding{Rule: "api_key_like", Start: loc[0], End: loc[1]})
		}
	}
	for i := len(findings) - 1; i >= 0; i-- {
		f := findings[i]
		if f.Start < 0 || f.End > len(ev.Payload) || f.Start >= f.End {
			continue
		}
		for j := f.Start; j < f.End; j++ {
			ev.Payload[j] = '*'
		}
	}
	return ev, nil
}

func (m *maskProc) Close() error { return nil }
