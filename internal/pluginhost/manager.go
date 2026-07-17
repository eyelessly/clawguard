package pluginhost

import (
	"fmt"
	"log"
	"sync"

	pluginv1 "clawguard/api/plugin/v1"
	"clawguard/internal/config"
	"clawguard/internal/event"
)

// Manager owns the active processor/sink clients.
type Manager struct {
	mu         sync.RWMutex
	cfg        config.Config
	processors []*Client
	sinks      []*Client
}

func NewManager(cfg config.Config) *Manager {
	return &Manager{cfg: cfg}
}

func (m *Manager) Load() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.loadLocked()
}

func (m *Manager) loadLocked() error {
	m.stopLocked()
	var procs []*Client
	var sinks []*Client

	for _, e := range m.cfg.Processors {
		if e.Disabled {
			continue
		}
		bin, err := ResolveBinary(m.cfg.PluginDir, e, "processor")
		if err != nil {
			return fmt.Errorf("processor %s: %w", e.Name, err)
		}
		c, err := Start(bin, e, "processor")
		if err != nil {
			return err
		}
		procs = append(procs, c)
	}
	for _, e := range m.cfg.Sinks {
		if e.Disabled {
			continue
		}
		bin, err := ResolveBinary(m.cfg.PluginDir, e, "sink")
		if err != nil {
			return fmt.Errorf("sink %s: %w", e.Name, err)
		}
		c, err := Start(bin, e, "sink")
		if err != nil {
			for _, p := range procs {
				p.Kill()
			}
			return err
		}
		sinks = append(sinks, c)
	}
	m.processors = procs
	m.sinks = sinks
	return nil
}

func (m *Manager) Reload(cfg config.Config) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
	if err := m.loadLocked(); err != nil {
		log.Printf("plugin reload failed: %v", err)
		return err
	}
	log.Printf("plugin reload ok processors=%d sinks=%d", len(m.processors), len(m.sinks))
	return nil
}

func (m *Manager) stopLocked() {
	for _, c := range m.processors {
		_ = c.Close()
	}
	for _, c := range m.sinks {
		_ = c.Close()
	}
	m.processors = nil
	m.sinks = nil
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.stopLocked()
}

func (m *Manager) PluginRefs() []event.PluginRef {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []event.PluginRef
	for _, c := range m.processors {
		out = append(out, c.PluginRef())
	}
	for _, c := range m.sinks {
		out = append(out, c.PluginRef())
	}
	return out
}

func (m *Manager) Processors() []*Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Client, len(m.processors))
	copy(out, m.processors)
	return out
}

func (m *Manager) SyncProcessors() []*Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Client
	for _, c := range m.processors {
		if c.Mode() != "async" {
			out = append(out, c)
		}
	}
	return out
}

func (m *Manager) AsyncProcessors() []*Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []*Client
	for _, c := range m.processors {
		if c.Mode() == "async" {
			out = append(out, c)
		}
	}
	return out
}

func (m *Manager) Sinks() []*Client {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Client, len(m.sinks))
	copy(out, m.sinks)
	return out
}

func (m *Manager) Infos() []pluginv1.PluginInfo {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []pluginv1.PluginInfo
	for _, c := range m.processors {
		out = append(out, c.InfoCached())
	}
	for _, c := range m.sinks {
		out = append(out, c.InfoCached())
	}
	return out
}
