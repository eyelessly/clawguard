package pluginsdk

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"

	pluginv1 "clawguard/api/plugin/v1"
	"clawguard/internal/event"
	"clawguard/internal/version"
)

// Handler is implemented by plugin binaries.
type Handler interface {
	Info() pluginv1.PluginInfo
	Configure(cfg pluginv1.PluginConfig) error
	Process(ev *event.CaptureEvent) (*event.CaptureEvent, error) // processors
	Emit(ev *event.CaptureEvent) error                          // sinks
	Close() error
}

// FillInfo fills version fields from ldflags.
func FillInfo(name, kind string) pluginv1.PluginInfo {
	return pluginv1.PluginInfo{
		Name:       name,
		Kind:       kind,
		Version:    version.Version,
		Commit:     version.Commit,
		BuildTime:  version.BuildTime,
		APIVersion: pluginv1.APIVersion,
	}
}

// MaybeVersionFlag exits if argv asks for -version / --version.
func MaybeVersionFlag(name string) {
	for _, a := range os.Args[1:] {
		if a == "-version" || a == "--version" {
			fmt.Printf("%s %s\n", name, version.String())
			os.Exit(0)
		}
	}
}

// Serve runs the length-prefixed JSON RPC loop on stdin/stdout.
func Serve(h Handler) {
	in := os.Stdin
	out := os.Stdout
	// Keep plugin logs on stderr so they don't corrupt the RPC stream.
	log.SetOutput(os.Stderr)
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	for {
		var req pluginv1.Request
		if err := pluginv1.ReadMessage(in, &req); err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("plugin read: %v", err)
			return
		}
		resp := handle(h, &req)
		if err := pluginv1.WriteMessage(out, resp); err != nil {
			log.Printf("plugin write: %v", err)
			return
		}
		if req.Method == pluginv1.MethodClose {
			return
		}
	}
}

func handle(h Handler, req *pluginv1.Request) pluginv1.Response {
	resp := pluginv1.Response{ID: req.ID, OK: true}
	switch req.Method {
	case pluginv1.MethodInfo:
		info := h.Info()
		if info.APIVersion == "" {
			info.APIVersion = pluginv1.APIVersion
		}
		b, err := json.Marshal(info)
		if err != nil {
			return errResp(req.ID, err)
		}
		resp.Result = b
	case pluginv1.MethodConfigure:
		var cfg pluginv1.PluginConfig
		if len(req.Params) > 0 {
			if err := json.Unmarshal(req.Params, &cfg); err != nil {
				return errResp(req.ID, err)
			}
		}
		if err := h.Configure(cfg); err != nil {
			return errResp(req.ID, err)
		}
		b, _ := json.Marshal(pluginv1.Status{Message: "ok"})
		resp.Result = b
	case pluginv1.MethodProcess:
		var ev event.CaptureEvent
		if err := json.Unmarshal(req.Params, &ev); err != nil {
			return errResp(req.ID, err)
		}
		out, err := h.Process(&ev)
		if err != nil {
			return errResp(req.ID, err)
		}
		if out == nil {
			out = &ev
		}
		b, err := json.Marshal(out)
		if err != nil {
			return errResp(req.ID, err)
		}
		resp.Result = b
	case pluginv1.MethodEmit:
		var ev event.CaptureEvent
		if err := json.Unmarshal(req.Params, &ev); err != nil {
			return errResp(req.ID, err)
		}
		if err := h.Emit(&ev); err != nil {
			return errResp(req.ID, err)
		}
		b, _ := json.Marshal(pluginv1.Status{Message: "ok"})
		resp.Result = b
	case pluginv1.MethodClose:
		if err := h.Close(); err != nil {
			return errResp(req.ID, err)
		}
		b, _ := json.Marshal(pluginv1.Status{Message: "closed"})
		resp.Result = b
	default:
		return errResp(req.ID, fmt.Errorf("unknown method %q", req.Method))
	}
	return resp
}

func errResp(id uint64, err error) pluginv1.Response {
	return pluginv1.Response{ID: id, OK: false, Error: err.Error()}
}

// SinkOnly provides no-op Process for sink plugins.
type SinkOnly struct{}

func (SinkOnly) Process(ev *event.CaptureEvent) (*event.CaptureEvent, error) { return ev, nil }

// ProcessorOnly rejects Emit for processor plugins.
type ProcessorOnly struct{}

func (ProcessorOnly) Emit(*event.CaptureEvent) error { return fmt.Errorf("not a sink") }
