package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type PluginEntry struct {
	Name     string         `yaml:"name"`
	Disabled bool           `yaml:"disabled"`
	Settings map[string]any `yaml:"settings,omitempty"`
	// Path overrides binary path; default is plugin_dir/clawguard-{kind}-{name} or clawguard-sink-{name}
	Path string `yaml:"path,omitempty"`
	// Mode for processors: "sync" (mutating gate before sinks) or "async" (observational side-path).
	// Empty -> defaults: detect=async, mask=sync, others=sync.
	Mode string `yaml:"mode,omitempty"`
}


type Config struct {
	PluginDir   string        `yaml:"plugin_dir"`
	Processors  []PluginEntry `yaml:"processors"`
	Sinks       []PluginEntry `yaml:"sinks"`
	SinkQueue   int           `yaml:"sink_queue"`    // per-sink queue size
	HTTPPort    int           `yaml:"http_port"`     // metrics (+ optional debug if builtin)
}

func Default() Config {
	return Config{
		PluginDir: "/var/lib/clawguard/plugins",
		Processors: []PluginEntry{
			{Name: "detect", Mode: "async", Disabled: false},
			{Name: "mask", Mode: "sync", Disabled: true},
		},
		Sinks: []PluginEntry{
			{
				Name: "file",
				Settings: map[string]any{
					"path": "/var/log/clawguard/plaintext.jsonl",
				},
			},
		},
		SinkQueue: 256,
		HTTPPort:  8080,
	}
}

// EffectiveMode returns sync|async for a processor entry.
func (e PluginEntry) EffectiveMode() string {
	m := strings.ToLower(strings.TrimSpace(e.Mode))
	switch m {
	case "sync", "async":
		return m
	}
	switch e.Name {
	case "detect":
		return "async"
	case "mask":
		return "sync"
	default:
		return "sync"
	}
}

func Load(path string) (Config, error) {
	cfg := Default()
	if path == "" {
		path = strings.TrimSpace(os.Getenv("CLAWGUARD_CONFIG"))
	}
	if path == "" {
		path = "/etc/clawguard/config.yaml"
	}
	b, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			normalizeProcessorModes(&cfg)
			applyEnvOverrides(&cfg)
			return cfg, nil
		}
		return cfg, err
	}
	if err := yaml.Unmarshal(b, &cfg); err != nil {
		return cfg, fmt.Errorf("parse %s: %w", path, err)
	}
	normalizeProcessorModes(&cfg)
	if cfg.SinkQueue <= 0 {
		cfg.SinkQueue = 256
	}
	if cfg.HTTPPort <= 0 {
		cfg.HTTPPort = 8080
	}
	if cfg.PluginDir == "" {
		cfg.PluginDir = "/var/lib/clawguard/plugins"
	}
	normalizeProcessorModes(&cfg)
	applyEnvOverrides(&cfg)
	return cfg, nil
}

func normalizeProcessorModes(cfg *Config) {
	for i := range cfg.Processors {
		cfg.Processors[i].Mode = cfg.Processors[i].EffectiveMode()
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := strings.TrimSpace(os.Getenv("CLAWGUARD_PLUGIN_DIR")); v != "" {
		cfg.PluginDir = v
	}
	// Enable otel sink when OTEL endpoint set.
	if ep := strings.TrimSpace(os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")); ep != "" {
		ensureSink(cfg, "otel", map[string]any{"endpoint": ep}, false)
	}
	// Debug UI sink
	ui := strings.TrimSpace(strings.ToLower(os.Getenv("CLAWGUARD_DEBUG_UI")))
	switch ui {
	case "0", "false", "off", "no":
		disableSink(cfg, "debugws")
	case "1", "true", "on", "yes":
		ensureSink(cfg, "debugws", map[string]any{"listen": ":8081"}, false)
	}
	if p := strings.TrimSpace(os.Getenv("CLAWGUARD_PLAINTEXT_LOG")); p != "" {
		ensureSink(cfg, "file", map[string]any{"path": p}, false)
	}
}

func ensureSink(cfg *Config, name string, settings map[string]any, disabled bool) {
	for i := range cfg.Sinks {
		if cfg.Sinks[i].Name == name {
			cfg.Sinks[i].Disabled = disabled
			if cfg.Sinks[i].Settings == nil {
				cfg.Sinks[i].Settings = map[string]any{}
			}
			for k, v := range settings {
				cfg.Sinks[i].Settings[k] = v
			}
			return
		}
	}
	cfg.Sinks = append(cfg.Sinks, PluginEntry{Name: name, Disabled: disabled, Settings: settings})
}

func disableSink(cfg *Config, name string) {
	for i := range cfg.Sinks {
		if cfg.Sinks[i].Name == name {
			cfg.Sinks[i].Disabled = true
			return
		}
	}
}

// BinaryName returns the conventional executable name for a plugin.
func BinaryName(kind, name string) string {
	switch kind {
	case "processor":
		return "clawguard-processor-" + name
	default:
		return "clawguard-sink-" + name
	}
}
