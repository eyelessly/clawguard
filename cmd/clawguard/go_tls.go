package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/cilium/ebpf/link"
)

func parseRuntimes(env string) (wantOpenSSL, wantGo bool) {
	env = strings.TrimSpace(strings.ToLower(env))
	if env == "" {
		return true, true
	}
	for _, p := range strings.Split(env, ",") {
		switch strings.TrimSpace(p) {
		case "openssl", "ssl", "libssl":
			wantOpenSSL = true
		case "go", "gotls", "crypto/tls":
			wantGo = true
		}
	}
	if !wantOpenSSL && !wantGo {
		return true, true
	}
	return wantOpenSSL, wantGo
}

func (cw *containerWatch) attachGoTLS(containerID string, rootPID int) (link.Link, error) {
	if cw.objs.ProbeGoTlsWrite == nil {
		return nil, fmt.Errorf("ProbeGoTlsWrite not loaded")
	}
	exePath := fmt.Sprintf("/proc/%d/exe", rootPID)
	resolved, err := filepath.EvalSymlinks(exePath)
	if err != nil {
		resolved = exePath
	}
	// Prefer path under container root when available.
	rootExe := filepath.Join(fmt.Sprintf("/proc/%d/root", rootPID), strings.TrimPrefix(resolved, "/"))
	candidates := []string{exePath, resolved, rootExe}
	var lastErr error
	for _, path := range candidates {
		if path == "" {
			continue
		}
		if _, err := os.Stat(path); err != nil {
			lastErr = err
			continue
		}
		if !isGoBinary(path) {
			lastErr = fmt.Errorf("%s is not a Go binary", path)
			continue
		}
		off, symName, err := resolveGoTLSWriteOffset(path)
		if err != nil {
			lastErr = err
			continue
		}
		ex, err := link.OpenExecutable(path)
		if err != nil {
			lastErr = err
			continue
		}
		up, err := ex.Uprobe("", cw.objs.ProbeGoTlsWrite, &link.UprobeOptions{Address: off})
		if err != nil {
			lastErr = err
			continue
		}
		log.Printf("attached go crypto/tls Write uprobe: container=%s exe=%s sym=%s off=%#x", shortID(containerID), path, symName, off)
		return up, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no go executable found for pid %d", rootPID)
	}
	return nil, lastErr
}
