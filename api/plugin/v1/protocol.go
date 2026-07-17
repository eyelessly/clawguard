package pluginv1

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"

	"clawguard/internal/event"
)

const APIVersion = "1"

const (
	MethodInfo      = "info"
	MethodConfigure = "configure"
	MethodProcess   = "process"
	MethodEmit      = "emit"
	MethodClose     = "close"
)

type Request struct {
	ID     uint64          `json:"id"`
	Method string          `json:"method"`
	Params json.RawMessage `json:"params,omitempty"`
}

type Response struct {
	ID     uint64          `json:"id"`
	OK     bool            `json:"ok"`
	Error  string          `json:"error,omitempty"`
	Result json.RawMessage `json:"result,omitempty"`
}

type PluginInfo struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"` // processor | sink
	Version    string `json:"version"`
	Commit     string `json:"commit"`
	BuildTime  string `json:"build_time"`
	APIVersion string `json:"api_version"`
}

type PluginConfig struct {
	Settings map[string]any `json:"settings,omitempty"`
}

type Status struct {
	Message string `json:"message,omitempty"`
}

// WriteMessage writes a length-prefixed JSON frame (4-byte big-endian length).
func WriteMessage(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	var hdr [4]byte
	binary.BigEndian.PutUint32(hdr[:], uint32(len(b)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// ReadMessage reads one length-prefixed JSON frame into dst.
func ReadMessage(r io.Reader, dst any) error {
	var hdr [4]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(hdr[:])
	if n == 0 || n > 256<<20 {
		return fmt.Errorf("invalid frame length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return err
	}
	return json.Unmarshal(buf, dst)
}

func MarshalParams(v any) (json.RawMessage, error) {
	if v == nil {
		return nil, nil
	}
	return json.Marshal(v)
}

func UnmarshalResult(raw json.RawMessage, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}

// CaptureEvent aliases pipeline event for RPC payloads.
type CaptureEvent = event.CaptureEvent
