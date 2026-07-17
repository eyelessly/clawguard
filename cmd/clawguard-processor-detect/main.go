package main

import (
	"regexp"

	pluginv1 "clawguard/api/plugin/v1"
	"clawguard/internal/event"
	"clawguard/pkg/pluginsdk"
)

var apiKeyLike = regexp.MustCompile(`(?i)(sk-[a-z0-9]{16,}|api[_-]?key["\s:=]+[a-z0-9_\-]{8,})`)

func main() {
	pluginsdk.MaybeVersionFlag("clawguard-processor-detect")
	pluginsdk.Serve(&detectProc{})
}

type detectProc struct {
	pluginsdk.ProcessorOnly
}

func (d *detectProc) Info() pluginv1.PluginInfo {
	return pluginsdk.FillInfo("detect", "processor")
}

func (d *detectProc) Configure(pluginv1.PluginConfig) error { return nil }

func (d *detectProc) Process(ev *event.CaptureEvent) (*event.CaptureEvent, error) {
	if ev == nil {
		return ev, nil
	}
	locs := apiKeyLike.FindAllIndex(ev.Payload, -1)
	for _, loc := range locs {
		start, end := loc[0], loc[1]
		preview := string(ev.Payload[start:end])
		if len(preview) > 24 {
			preview = preview[:12] + "…" + preview[len(preview)-4:]
		}
		ev.Findings = append(ev.Findings, event.Finding{
			Rule:    "api_key_like",
			Start:   start,
			End:     end,
			Preview: preview,
		})
	}
	return ev, nil
}

func (d *detectProc) Close() error { return nil }
