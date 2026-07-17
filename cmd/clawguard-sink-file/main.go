// Command clawguard-sink-file is the reference sink plugin for ClawGuard.
//
// Copy this package when implementing a custom sink (ClickHouse, Kafka, ...):
//  1. Fill Info() via pluginsdk.FillInfo
//  2. Read settings in Configure
//  3. Persist each CaptureEvent in Emit (host already set clawguard_* / plugins[])
//  4. Flush in Close; call pluginsdk.Serve in main
//
// Contract: docs/plugin-contract.md
package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	pluginv1 "clawguard/api/plugin/v1"
	"clawguard/internal/event"
	"clawguard/pkg/pluginsdk"
)

func main() {
	pluginsdk.MaybeVersionFlag("clawguard-sink-file")
	pluginsdk.Serve(&fileSink{})
}

// fileSink appends one JSONL line per CaptureEvent.
type fileSink struct {
	pluginsdk.SinkOnly // Process is unused for sinks
	mu                 sync.Mutex
	path               string
	f                  *os.File
}

func (s *fileSink) Info() pluginv1.PluginInfo {
	return pluginsdk.FillInfo("file", "sink")
}

func (s *fileSink) Configure(cfg pluginv1.PluginConfig) error {
	path, _ := cfg.Settings["path"].(string)
	if path == "" {
		path = "/var/log/clawguard/plaintext.jsonl"
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	s.mu.Lock()
	if s.f != nil {
		_ = s.f.Close()
	}
	s.path = path
	s.f = f
	s.mu.Unlock()

	// Optional session header so operators can see which plugin build opened the file.
	meta := map[string]any{
		"type":       "session",
		"started_at": time.Now().UTC().Format(time.RFC3339Nano),
		"plugin":     s.Info(),
	}
	b, _ := json.Marshal(meta)
	_, _ = f.Write(append(b, '\n'))
	return nil
}

func (s *fileSink) Emit(ev *event.CaptureEvent) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f == nil {
		return fmt.Errorf("file sink not configured")
	}
	// payload is also in CaptureEvent.Payload ([]byte -> base64 in JSON);
	// payload_text is a convenience UTF-8 view for grepping / demos.
	type row struct {
		*event.CaptureEvent
		PayloadText string `json:"payload_text,omitempty"`
	}
	r := row{CaptureEvent: ev}
	if len(ev.Payload) > 0 {
		r.PayloadText = string(ev.Payload)
	}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	_, err = s.f.Write(append(b, '\n'))
	return err
}

func (s *fileSink) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.f != nil {
		err := s.f.Close()
		s.f = nil
		return err
	}
	return nil
}
