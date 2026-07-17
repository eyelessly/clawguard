package event

import "time"

// PluginRef identifies a loaded plugin binary for downstream audit.
type PluginRef struct {
	Name      string `json:"name"`
	Kind      string `json:"kind"` // processor | sink
	Version   string `json:"version"`
	Commit    string `json:"commit"`
	BuildTime string `json:"build_time,omitempty"`
}

// Finding is produced by detect processors.
type Finding struct {
	Rule    string `json:"rule"`
	Start   int    `json:"start"`
	End     int    `json:"end"`
	Preview string `json:"preview,omitempty"`
}

// CaptureEvent is the pipeline unit after TLS plaintext reassembly.
type CaptureEvent struct {
	Timestamp    time.Time  `json:"timestamp"`
	PID          uint32     `json:"pid"`
	TID          uint32     `json:"tid"`
	CallID       uint32     `json:"call_id"`
	OrigLen      uint32     `json:"orig_len"`
	CapturedLen  uint32     `json:"captured_len"`
	Truncated    bool       `json:"truncated"`
	HookType     uint32     `json:"hook_type"`
	Payload      []byte     `json:"payload"`
	ContainerID  string     `json:"container_id"`
	PodName      string     `json:"pod_name,omitempty"`
	PodNamespace string     `json:"pod_namespace,omitempty"`

	ClawguardVersion string      `json:"clawguard_version"`
	ClawguardCommit  string      `json:"clawguard_commit"`
	ClawguardEdition string      `json:"clawguard_edition"`
	Plugins          []PluginRef `json:"plugins,omitempty"`
	Findings         []Finding   `json:"findings,omitempty"`
}

// CloneShallow copies metadata and shares Payload bytes (caller must not mutate).
func (e *CaptureEvent) CloneShallow() *CaptureEvent {
	if e == nil {
		return nil
	}
	out := *e
	if len(e.Plugins) > 0 {
		out.Plugins = append([]PluginRef(nil), e.Plugins...)
	}
	if len(e.Findings) > 0 {
		out.Findings = append([]Finding(nil), e.Findings...)
	}
	return &out
}

// CloneDeep copies metadata and Payload.
func (e *CaptureEvent) CloneDeep() *CaptureEvent {
	out := e.CloneShallow()
	if out == nil {
		return nil
	}
	if len(e.Payload) > 0 {
		out.Payload = append([]byte(nil), e.Payload...)
	}
	return out
}
