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
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

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
		broadcast:  make(chan []byte),
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
		case client := <-h.register:
			h.mu.Lock()
			h.clients[client] = true
			h.mu.Unlock()
		case client := <-h.unregister:
			h.mu.Lock()
			if _, ok := h.clients[client]; ok {
				delete(h.clients, client)
				close(client.send)
			}
			h.mu.Unlock()
		case message := <-h.broadcast:
			h.mu.Lock()
			for client := range h.clients {
				select {
				case client.send <- message:
				default:
					close(client.send)
					delete(h.clients, client)
				}
			}
			h.mu.Unlock()
		}
	}
}

type PacketEvent struct {
	Timestamp    time.Time `json:"timestamp"`
	PID          uint32    `json:"pid"`
	TID          uint32    `json:"tid"`
	CallID       uint32    `json:"call_id"`
	OrigLen      uint32    `json:"orig_len"`
	CapturedLen  uint32    `json:"captured_len"`
	Truncated    bool      `json:"truncated"`
	HookType     uint32    `json:"hook_type"`
	Payload      string    `json:"payload"`
	ContainerID  string    `json:"container_id"`
	PodName      string    `json:"pod_name,omitempty"`
	PodNamespace string    `json:"pod_namespace,omitempty"`
}

func serveWs(hub *hub, w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("upgrade: %v", err)
		return
	}
	client := &wsClient{conn: conn, send: make(chan []byte, 256)}
	hub.register <- client

	go client.writePump()
	go client.readPump(hub)
}

func (c *wsClient) readPump(h *hub) {
	defer func() {
		h.unregister <- c
		c.conn.Close()
	}()
	for {
		_, _, err := c.conn.ReadMessage()
		if err != nil {
			break
		}
	}
}

func (c *wsClient) writePump() {
	defer func() {
		c.conn.Close()
	}()
	for {
		message, ok := <-c.send
		if !ok {
			c.conn.WriteMessage(websocket.CloseMessage, []byte{})
			return
		}
		w, err := c.conn.NextWriter(websocket.TextMessage)
		if err != nil {
			return
		}
		w.Write(message)
		if err := w.Close(); err != nil {
			return
		}
	}
}

// debugUIEnabled is true unless CLAWGUARD_DEBUG_UI is explicitly "0", "false", or "off".
func debugUIEnabled() bool {
	v := strings.TrimSpace(strings.ToLower(os.Getenv("CLAWGUARD_DEBUG_UI")))
	switch v {
	case "0", "false", "off", "no":
		return false
	default:
		return true
	}
}

func startHTTPServer(ctx context.Context, hub *hub, port int) {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	uiOn := debugUIEnabled()
	if uiOn {
		mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
			serveWs(hub, w, r)
		})

		fs := http.FileServer(http.Dir("/ui/dist"))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			path := r.URL.Path
			ext := filepath.Ext(path)
			if ext != "" {
				var m string
				switch ext {
				case ".css":
					m = "text/css"
				case ".js":
					m = "application/javascript"
				case ".png":
					m = "image/png"
				case ".svg":
					m = "image/svg+xml"
				case ".html":
					m = "text/html"
				default:
					m = mime.TypeByExtension(ext)
				}
				if m != "" {
					w.Header().Set("Content-Type", m)
				}
			}
			fs.ServeHTTP(w, r)
		})
	} else {
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/" {
				http.NotFound(w, r)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			fmt.Fprintf(w, "ClawGuard metrics at /metrics (debug UI disabled via CLAWGUARD_DEBUG_UI)\n")
		})
	}

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		if uiOn {
			log.Printf("HTTP listening on http://0.0.0.0:%d (metrics=/metrics, debug UI on)", port)
		} else {
			log.Printf("HTTP listening on http://0.0.0.0:%d (metrics=/metrics, debug UI off)", port)
		}
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("listen: %s\n", err)
		}
	}()

	<-ctx.Done()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(shutdownCtx)
}

func broadcastPacket(hub *hub, event PacketEvent) {
	if hub == nil || !debugUIEnabled() {
		return
	}
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("marshal packet: %v", err)
		return
	}
	hub.broadcast <- data
}
