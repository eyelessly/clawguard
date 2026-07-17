package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	pluginv1 "clawguard/api/plugin/v1"
	"clawguard/internal/event"
	"clawguard/pkg/pluginsdk"

	"github.com/gorilla/websocket"
)

func main() {
	pluginsdk.MaybeVersionFlag("clawguard-sink-debugws")
	pluginsdk.Serve(&debugWS{})
}

type debugWS struct {
	pluginsdk.SinkOnly
	hub    *hub
	cancel context.CancelFunc
}

func (s *debugWS) Info() pluginv1.PluginInfo {
	return pluginsdk.FillInfo("debugws", "sink")
}

func (s *debugWS) Configure(cfg pluginv1.PluginConfig) error {
	listen, _ := cfg.Settings["listen"].(string)
	if listen == "" {
		listen = ":8081"
	}
	uiDir, _ := cfg.Settings["ui_dir"].(string)
	if uiDir == "" {
		uiDir = "/ui/dist"
	}
	s.hub = newHub()
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go s.hub.run(ctx)
	go startHTTP(ctx, s.hub, listen, uiDir)
	log.Printf("debugws sink listening on %s", listen)
	return nil
}

func (s *debugWS) Emit(ev *event.CaptureEvent) error {
	if s.hub == nil {
		return nil
	}
	type pkt struct {
		Timestamp          time.Time         `json:"timestamp"`
		PID                uint32            `json:"pid"`
		TID                uint32            `json:"tid"`
		CallID             uint32            `json:"call_id"`
		OrigLen            uint32            `json:"orig_len"`
		CapturedLen        uint32            `json:"captured_len"`
		Truncated          bool              `json:"truncated"`
		HookType           uint32            `json:"hook_type"`
		Payload            string            `json:"payload"`
		ContainerID        string            `json:"container_id"`
		PodName            string            `json:"pod_name,omitempty"`
		PodNamespace       string            `json:"pod_namespace,omitempty"`
		ClawguardVersion   string            `json:"clawguard_version"`
		ClawguardCommit    string            `json:"clawguard_commit"`
		Plugins            []event.PluginRef `json:"plugins,omitempty"`
	}
	p := pkt{
		Timestamp:        ev.Timestamp,
		PID:              ev.PID,
		TID:              ev.TID,
		CallID:           ev.CallID,
		OrigLen:          ev.OrigLen,
		CapturedLen:      ev.CapturedLen,
		Truncated:        ev.Truncated,
		HookType:         ev.HookType,
		Payload:          string(ev.Payload),
		ContainerID:      ev.ContainerID,
		PodName:          ev.PodName,
		PodNamespace:     ev.PodNamespace,
		ClawguardVersion: ev.ClawguardVersion,
		ClawguardCommit:  ev.ClawguardCommit,
		Plugins:          ev.Plugins,
	}
	data, err := json.Marshal(p)
	if err != nil {
		return err
	}
	select {
	case s.hub.broadcast <- data:
	default:
	}
	return nil
}

func (s *debugWS) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

var upgrader = websocket.Upgrader{CheckOrigin: func(r *http.Request) bool { return true }}

type wsClient struct {
	conn *websocket.Conn
	send chan []byte
}

type hub struct {
	clients    map[*wsClient]bool
	broadcast  chan []byte
	register   chan *wsClient
	unregister chan *wsClient
	mu         sync.Mutex
}

func newHub() *hub {
	return &hub{
		broadcast:  make(chan []byte, 64),
		register:   make(chan *wsClient),
		unregister: make(chan *wsClient),
		clients:    make(map[*wsClient]bool),
	}
}

func (h *hub) run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case c := <-h.register:
			h.mu.Lock()
			h.clients[c] = true
			h.mu.Unlock()
		case c := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[c]; ok {
				delete(h.clients, c)
				close(c.send)
			}
			h.mu.Unlock()
		case msg := <-h.broadcast:
			h.mu.Lock()
			for c := range h.clients {
				select {
				case c.send <- msg:
				default:
					close(c.send)
					delete(h.clients, c)
				}
			}
			h.mu.Unlock()
		}
	}
}

func startHTTP(ctx context.Context, h *hub, listen, uiDir string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		conn, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		c := &wsClient{conn: conn, send: make(chan []byte, 256)}
		h.register <- c
		go func() {
			defer func() {
				h.unregister <- c
				conn.Close()
			}()
			for {
				if _, _, err := conn.ReadMessage(); err != nil {
					return
				}
			}
		}()
		go func() {
			defer conn.Close()
			for msg := range c.send {
				if err := conn.WriteMessage(websocket.TextMessage, msg); err != nil {
					return
				}
			}
		}()
	})
	if st, err := os.Stat(uiDir); err == nil && st.IsDir() {
		fs := http.FileServer(http.Dir(uiDir))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			ext := filepath.Ext(r.URL.Path)
			if ext != "" {
				if m := mime.TypeByExtension(ext); m != "" {
					w.Header().Set("Content-Type", m)
				}
			}
			fs.ServeHTTP(w, r)
		})
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(w, "ClawGuard debugws plugin (UI dir missing)\n")
		})
	}
	srv := &http.Server{Addr: listen, Handler: mux}
	go func() {
		<-ctx.Done()
		_ = srv.Shutdown(context.Background())
	}()
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("debugws listen: %v", err)
	}
}
