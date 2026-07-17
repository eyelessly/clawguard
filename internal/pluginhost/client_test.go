package pluginhost_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"clawguard/internal/config"
	"clawguard/internal/event"
	"clawguard/internal/pipeline"
	"clawguard/internal/pluginhost"
)

func TestFileSinkRoundTrip(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "clawguard-sink-file")
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("go", "build", "-o", bin, "./cmd/clawguard-sink-file")
	cmd.Dir = root
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build plugin: %v\n%s", err, out)
	}

	logPath := filepath.Join(dir, "out.jsonl")
	cfg := config.Config{
		PluginDir: dir,
		Sinks: []config.PluginEntry{{
			Name: "file",
			Settings: map[string]any{
				"path": logPath,
			},
		}},
		SinkQueue: 16,
	}
	mgr := pluginhost.NewManager(cfg)
	if err := mgr.Load(); err != nil {
		t.Fatal(err)
	}
	p := pipeline.New(mgr, 16, nil)
	p.Start(t.Context())
	defer p.Close()

	p.Emit(&event.CaptureEvent{
		PID:     1,
		Payload: []byte("hello-plugin-MARKER"),
	})

	deadline := time.Now().Add(5 * time.Second)
	for {
		b, err := os.ReadFile(logPath)
		if err == nil {
			s := string(b)
			if strings.Contains(s, "hello-plugin-MARKER") &&
				strings.Contains(s, "clawguard_version") &&
				strings.Contains(s, `"name":"file"`) {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("timeout waiting for file sink; content=%q err=%v", string(b), err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}
