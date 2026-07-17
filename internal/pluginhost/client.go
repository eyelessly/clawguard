package pluginhost

import (
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"sync/atomic"

	pluginv1 "clawguard/api/plugin/v1"
	"clawguard/internal/config"
	"clawguard/internal/event"
)

// Client is an RPC client to one plugin subprocess (JSON frames on stdin/stdout).
type Client struct {
	name string
	kind string
	mode string // sync | async (processors); unused for sinks
	info pluginv1.PluginInfo
	cmd  *exec.Cmd
	stdin  io.WriteCloser
	stdout io.ReadCloser
	mu     sync.Mutex
	nextID atomic.Uint64
}

func Start(bin string, entry config.PluginEntry, kind string) (*Client, error) {
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(), "CLAWGUARD_PLUGIN=1")
	cmd.Stderr = os.Stderr
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return nil, err
	}
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		_ = stdout.Close()
		return nil, err
	}
	mode := ""
	if kind == "processor" {
		mode = entry.EffectiveMode()
	}
	c := &Client{
		name:   entry.Name,
		kind:   kind,
		mode:   mode,
		cmd:    cmd,
		stdin:  stdin,
		stdout: stdout,
	}
	info, err := c.Info()
	if err != nil {
		c.Kill()
		return nil, fmt.Errorf("plugin %s info: %w", entry.Name, err)
	}
	if info.APIVersion != "" && info.APIVersion != pluginv1.APIVersion {
		c.Kill()
		return nil, fmt.Errorf("plugin %s api_version=%s want %s", entry.Name, info.APIVersion, pluginv1.APIVersion)
	}
	c.info = info
	if c.info.Name == "" {
		c.info.Name = entry.Name
	}
	if c.info.Kind == "" {
		c.info.Kind = kind
	}
	cfg := pluginv1.PluginConfig{Settings: entry.Settings}
	if err := c.Configure(cfg); err != nil {
		c.Kill()
		return nil, fmt.Errorf("plugin %s configure: %w", entry.Name, err)
	}
	if kind == "processor" {
		log.Printf("plugin loaded name=%s kind=%s mode=%s version=%s commit=%s path=%s", c.info.Name, c.info.Kind, c.mode, c.info.Version, c.info.Commit, bin)
	} else {
		log.Printf("plugin loaded name=%s kind=%s version=%s commit=%s path=%s", c.info.Name, c.info.Kind, c.info.Version, c.info.Commit, bin)
	}
	return c, nil
}

func (c *Client) Mode() string { return c.mode }

func (c *Client) InfoCached() pluginv1.PluginInfo { return c.info }

func (c *Client) call(method string, params any, result any) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	id := c.nextID.Add(1)
	raw, err := pluginv1.MarshalParams(params)
	if err != nil {
		return err
	}
	req := pluginv1.Request{ID: id, Method: method, Params: raw}
	if err := pluginv1.WriteMessage(c.stdin, req); err != nil {
		return err
	}
	var resp pluginv1.Response
	if err := pluginv1.ReadMessage(c.stdout, &resp); err != nil {
		return err
	}
	if resp.ID != id {
		return fmt.Errorf("plugin %s: response id mismatch", c.name)
	}
	if !resp.OK {
		return fmt.Errorf("plugin %s %s: %s", c.name, method, resp.Error)
	}
	if result != nil {
		return pluginv1.UnmarshalResult(resp.Result, result)
	}
	return nil
}

func (c *Client) Info() (pluginv1.PluginInfo, error) {
	var info pluginv1.PluginInfo
	err := c.call(pluginv1.MethodInfo, nil, &info)
	return info, err
}

func (c *Client) Configure(cfg pluginv1.PluginConfig) error {
	return c.call(pluginv1.MethodConfigure, cfg, &pluginv1.Status{})
}

func (c *Client) Process(ev *event.CaptureEvent) (*event.CaptureEvent, error) {
	var out event.CaptureEvent
	if err := c.call(pluginv1.MethodProcess, ev, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func (c *Client) Emit(ev *event.CaptureEvent) error {
	return c.call(pluginv1.MethodEmit, ev, &pluginv1.Status{})
}

func (c *Client) Close() error {
	err := c.call(pluginv1.MethodClose, nil, &pluginv1.Status{})
	c.Kill()
	return err
}

func (c *Client) Kill() {
	if c.cmd != nil && c.cmd.Process != nil {
		_ = c.cmd.Process.Kill()
		_, _ = c.cmd.Process.Wait()
	}
	if c.stdin != nil {
		_ = c.stdin.Close()
	}
	if c.stdout != nil {
		_ = c.stdout.Close()
	}
}

func (c *Client) PluginRef() event.PluginRef {
	return event.PluginRef{
		Name:      c.info.Name,
		Kind:      c.info.Kind,
		Version:   c.info.Version,
		Commit:    c.info.Commit,
		BuildTime: c.info.BuildTime,
	}
}

// ResolveBinary finds the plugin executable.
func ResolveBinary(dir string, entry config.PluginEntry, kind string) (string, error) {
	if entry.Path != "" {
		return entry.Path, nil
	}
	name := config.BinaryName(kind, entry.Name)
	candidates := []string{
		filepath.Join(dir, name),
		filepath.Join(dir, entry.Name),
	}
	for _, p := range candidates {
		if st, err := os.Stat(p); err == nil && !st.IsDir() {
			return p, nil
		}
	}
	// Also check PATH
	if p, err := exec.LookPath(name); err == nil {
		return p, nil
	}
	return "", fmt.Errorf("plugin binary not found for %s (looked in %s for %s)", entry.Name, dir, name)
}