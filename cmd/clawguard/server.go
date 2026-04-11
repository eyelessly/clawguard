package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"mime"
	"net/http"
	"path/filepath"
	"sync"
	"time"

	"github.com/gorilla/websocket"
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
	Timestamp   time.Time `json:"timestamp"`
	PID         uint32    `json:"pid"`
	TID         uint32    `json:"tid"`
	CallID      uint32    `json:"call_id"`
	OrigLen     uint32    `json:"orig_len"`
	CapturedLen uint32    `json:"captured_len"`
	Truncated   bool      `json:"truncated"`
	HookType    uint32    `json:"hook_type"`
	Payload     string    `json:"payload"`
	ContainerID string    `json:"container_id"`
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

func startHTTPServer(ctx context.Context, hub *hub, port int) {
	mux := http.NewServeMux()

	// WebSocket endpoint
	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) {
		serveWs(hub, w, r)
	})

	// Serve static files from ui/dist with explicit MIME type handling
	fs := http.FileServer(http.Dir("/ui/dist"))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		ext := filepath.Ext(path)

		// Robust MIME handling for minimal containers
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

	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", port),
		Handler: mux,
	}

	go func() {
		log.Printf("Web UI listening on http://0.0.0.0:%d", port)
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
	data, err := json.Marshal(event)
	if err != nil {
		log.Printf("marshal packet: %v", err)
		return
	}
	hub.broadcast <- data
}
