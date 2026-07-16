package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
)

// Matches struct ssl_event in bpf/ssl_write.bpf.c (packed layout, no padding between fields).
type sslEvent struct {
	PID       uint32
	TID       uint32
	CallID    uint32
	OrigLen   uint32
	TotalLen  uint32
	Truncated uint32
	FragIdx   uint32
	FragCnt   uint32
	ChunkLen  uint32
	HookType  uint32
	Payload   [512]byte
}

const (
	maxChunkPayload = 512
	maxCaptureBytes = 16384
	reassemblyTTL   = 2 * time.Second
)

type reassemblyKey struct {
	PID    uint32
	TID    uint32
	CallID uint32
}

type reassemblyState struct {
	origLen   uint32
	totalLen  uint32
	truncated bool
	fragCnt   uint32
	frags     map[uint32][]byte
	firstAt   time.Time
	lastAt    time.Time
}

var debugLog = func(format string, args ...any) {}
var logPayloadMaxBytes = maxCaptureBytes

func init() {
	if os.Getenv("CLAWGUARD_DEBUG") != "" {
		debugLog = func(format string, args ...any) {
			log.Printf("[debug] "+format, args...)
		}
	}
	logPayloadMaxBytes = parseLogPayloadMax(os.Getenv("CLAWGUARD_PAYLOAD_PREVIEW_MAX"))
}

func parseLogPayloadMax(v string) int {
	v = strings.TrimSpace(v)
	if v == "" {
		return maxCaptureBytes
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		log.Printf("warning: CLAWGUARD_PAYLOAD_PREVIEW_MAX=%q invalid, fallback to %d", v, maxCaptureBytes)
		return maxCaptureBytes
	}
	if n < 0 {
		log.Printf("warning: CLAWGUARD_PAYLOAD_PREVIEW_MAX=%q negative, fallback to %d", v, maxCaptureBytes)
		return maxCaptureBytes
	}
	if n > maxCaptureBytes {
		log.Printf("warning: CLAWGUARD_PAYLOAD_PREVIEW_MAX=%d exceeds cap %d, using %d", n, maxCaptureBytes, maxCaptureBytes)
		return maxCaptureBytes
	}
	return n
}

// parseLabelFilter parses CLAWGUARD_LABEL: comma-separated key=value pairs (AND).
// Empty or unset env → nil slice (no filter). Example: `clawguard.monitor=true` or `a=1,b=2`.
func parseLabelFilter(env string) ([]labelPair, error) {
	env = strings.TrimSpace(env)
	if env == "" {
		return nil, nil
	}
	var out []labelPair
	for _, part := range strings.Split(env, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		i := strings.IndexByte(part, '=')
		if i <= 0 {
			return nil, fmt.Errorf("segment %q: want key=value", part)
		}
		key := strings.TrimSpace(part[:i])
		val := strings.TrimSpace(part[i+1:])
		if key == "" {
			return nil, fmt.Errorf("segment %q: empty key", part)
		}
		out = append(out, labelPair{key: key, val: val})
	}
	if len(out) == 0 {
		return nil, nil
	}
	return out, nil
}

func formatLabelFilterLog(pairs []labelPair) string {
	var b strings.Builder
	for i, p := range pairs {
		if i > 0 {
			b.WriteString(", ")
		}
		b.WriteString(p.key)
		b.WriteByte('=')
		b.WriteString(p.val)
	}
	return b.String()
}

func (cw *containerWatch) labelsMatch(labels map[string]string) bool {
	if len(cw.labelPairs) == 0 {
		return true
	}
	if labels == nil {
		return false
	}
	for _, p := range cw.labelPairs {
		v, ok := labels[p.key]
		if !ok || v != p.val {
			return false
		}
	}
	return true
}

func logRuntimeContext() {
	if b, err := os.ReadFile("/proc/sys/kernel/osrelease"); err == nil {
		log.Printf("kernel osrelease: %s", strings.TrimSpace(string(b)))
	} else {
		log.Printf("kernel osrelease: (read error: %v)", err)
	}
	if fi, err := os.Stat("/sys/kernel/btf/vmlinux"); err == nil {
		log.Printf("BTF: /sys/kernel/btf/vmlinux present (size=%d)", fi.Size())
	} else {
		log.Printf("BTF: /sys/kernel/btf/vmlinux stat (%v) — CO-RE features may vary", err)
	}
	if b, err := os.ReadFile("/proc/version"); err == nil {
		log.Printf("/proc/version: %s", strings.TrimSpace(string(b)))
	}
}

// labelPair is one required Docker label (Config.Labels key → exact value).
type labelPair struct {
	key, val string
}

type containerWatch struct {
	mu              sync.Mutex
	byID            map[string]*attachSet
	metaByID        map[string]targetMeta
	objs            *ssl_writeObjects
	ringReader      *ringbuf.Reader
	selfContainerID string      // 12- or 64-hex; skip attaching to ourselves (cgroup, hostname, or Docker API pid match)
	labelPairs      []labelPair // empty = monitor all non-self; non-empty = AND match on container labels
	hub             *hub
	otel            *otelEmitter
}

type attachSet struct {
	links       []link.Link
	containerID string
}

type targetMeta struct {
	podName       string
	podNamespace  string
	runtime       string
	containerName string
}

func main() {
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)
	log.SetOutput(os.Stdout)

	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer cancel()

	if os.Geteuid() != 0 {
		log.Println("warning: not running as root; eBPF uprobe attach usually requires privileges")
	}
	log.Printf("pid=%d CLAWGUARD_DEBUG=%q", os.Getpid(), os.Getenv("CLAWGUARD_DEBUG"))
	log.Printf("CLAWGUARD_PAYLOAD_PREVIEW_MAX=%d (display-only cap)", logPayloadMaxBytes)
	logRuntimeContext()

	otelOut, err := initOTel(ctx)
	if err != nil {
		log.Fatalf("otel: %v", err)
	}
	if otelOut != nil {
		defer otelOut.shutdown(context.Background())
	}

	objs := &ssl_writeObjects{}
	log.Println("loading BPF collection (ssl_write + ssl_write_ex)...")
	if err := loadSsl_writeObjects(objs, nil); err != nil {
		log.Fatalf("load bpf: %v (hint: 'unbounded' on bpf_probe_read_user = need updated BPF object; lockdown/permission denied may be kernel lockdown or missing CAP_BPF)", err)
	}
	defer objs.Close()
	log.Println("BPF collection loaded OK")

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("ringbuf: %v", err)
	}
	defer rd.Close()

	cw := &containerWatch{
		byID:       make(map[string]*attachSet),
		metaByID:   make(map[string]targetMeta),
		objs:       objs,
		ringReader: rd,
		hub:        newHub(),
		otel:       otelOut,
	}

	go cw.hub.run(ctx)
	go startHTTPServer(ctx, cw.hub, 8080)
	go cw.readLoop(ctx)

	if os.Getenv("KUBERNETES_SERVICE_HOST") != "" {
		selfID := detectSelfContainerID()
		cw.selfContainerID = selfID
		if selfID != "" {
			log.Printf("self container id (skip attach): %s", shortID(selfID))
		}
		log.Println("ClawGuard: Kubernetes mode (pod annotation select + SSL_write/SSL_write_ex)")
		if err := cw.runK8sMode(ctx); err != nil && !errors.Is(err, context.Canceled) {
			log.Fatalf("k8s mode: %v", err)
		}
		cw.detachAll()
		return
	}

	cw.runDockerMode(ctx)
}

func (cw *containerWatch) runDockerMode(ctx context.Context) {
	dockerSock := "unix:///var/run/docker.sock"
	if v := os.Getenv("DOCKER_HOST"); v != "" {
		dockerSock = v
	}

	cli, err := client.NewClientWithOpts(
		client.WithHost(dockerSock),
		client.WithAPIVersionNegotiation(),
	)
	if err != nil {
		log.Fatalf("docker client: %v", err)
	}
	defer cli.Close()

	selfID := detectSelfContainerID()
	if selfID == "" {
		selfID = detectSelfViaDockerAPI(ctx, cli)
	}
	cw.selfContainerID = selfID
	if selfID != "" {
		log.Printf("self container id (skip attach): %s", shortID(selfID))
	} else {
		log.Println("warning: could not detect self container id (cgroup/hostname/docker API); may try to attach to this manager (no libssl). Use --pid=host for pid-based self-detection.")
	}

	labelPairs, err := parseLabelFilter(os.Getenv("CLAWGUARD_LABEL"))
	if err != nil {
		log.Fatalf("CLAWGUARD_LABEL: %v", err)
	}
	cw.labelPairs = labelPairs
	if len(labelPairs) > 0 {
		log.Printf("monitor filter (all must match): %s", formatLabelFilterLog(labelPairs))
	} else {
		log.Println("monitor filter: (none) all non-self containers with libssl")
	}

	if err := cw.scanRunning(ctx, cli); err != nil {
		log.Printf("initial scan: %v", err)
	} else {
		cw.mu.Lock()
		n := len(cw.byID)
		cw.mu.Unlock()
		debugLog("initial scan done, attached containers: %d", n)
	}

	evCh, errCh := cli.Events(ctx, types.EventsOptions{})
	log.Println("ClawGuard: listening for Docker events + SSL_write/SSL_write_ex")

	for {
		select {
		case <-ctx.Done():
			cw.detachAll()
			return
		case err := <-errCh:
			if err != nil && !errors.Is(err, context.Canceled) {
				log.Printf("docker events error: %v", err)
			}
		case ev := <-evCh:
			debugLog("docker event type=%q action=%q actor=%q", ev.Type, ev.Action, shortID(ev.Actor.ID))
			cw.handleDockerEvent(ctx, cli, ev)
		}
	}
}

// detectSelfContainerID returns 12- or 64-char hex so we can skip the manager container.
// Cgroup works on many Linux hosts; Docker Desktop / linuxkit often has cgroup lines without
// "docker-<id>" (e.g. only "0::/") — then use detectSelfViaDockerAPI after this returns "".
func detectSelfContainerID() string {
	if id := dockerIDFromCgroup(); id != "" {
		debugLog("self id from /proc/self/cgroup: %s", shortID(id))
		return id
	}
	return dockerIDFromHostname()
}

// detectSelfViaDockerAPI finds the running container whose State.Pid equals our process pid.
// Matches README --pid=host so the manager PID is the same as Docker's reported container PID.
func detectSelfViaDockerAPI(ctx context.Context, cli *client.Client) string {
	me := os.Getpid()
	list, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		debugLog("detectSelfViaDockerAPI: ContainerList: %v", err)
		return ""
	}
	for _, c := range list {
		if c.State != "running" {
			continue
		}
		insp, err := cli.ContainerInspect(ctx, c.ID)
		if err != nil {
			continue
		}
		if insp.State.Pid != me {
			continue
		}
		id := strings.TrimPrefix(strings.ToLower(c.ID), "sha256:")
		debugLog("detectSelfViaDockerAPI: pid %d matches container id %s", me, shortID(id))
		return id
	}
	return ""
}

func dockerIDFromCgroup() string {
	b, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	s := strings.ToLower(string(b))
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		// cgroup v2 + systemd: .../docker-<id>.scope
		if i := strings.Index(line, "docker-"); i >= 0 {
			rest := line[i+len("docker-"):]
			if j := strings.Index(rest, ".scope"); j > 0 {
				id := rest[:j]
				if isDockerHexID(id) {
					return id
				}
			}
		}
		// .../docker/<id>/...
		if i := strings.Index(line, "/docker/"); i >= 0 {
			id := takeLeadingHex(line[i+len("/docker/"):])
			if isDockerHexID(id) {
				return id
			}
		}
	}
	return ""
}

func takeLeadingHex(s string) string {
	n := 0
	for n < len(s) {
		c := s[n]
		if (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') {
			n++
			continue
		}
		break
	}
	return s[:n]
}

func isDockerHexID(id string) bool {
	n := len(id)
	if n != 12 && n != 64 {
		return false
	}
	for i := 0; i < n; i++ {
		c := id[i]
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return false
		}
	}
	return true
}

func dockerIDFromHostname() string {
	h, err := os.Hostname()
	if err != nil || len(h) < 12 {
		return ""
	}
	for _, r := range h {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') && (r < 'A' || r > 'F') {
			return ""
		}
	}
	if len(h) > 12 {
		h = h[:12]
	}
	return strings.ToLower(h)
}

func (cw *containerWatch) readLoop(ctx context.Context) {
	reassemblies := make(map[reassemblyKey]*reassemblyState)
	lastCleanup := time.Now()

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		record, err := cw.ringReader.Read()
		if err != nil {
			if errors.Is(err, ringbuf.ErrClosed) || errors.Is(err, context.Canceled) {
				return
			}
			if errors.Is(err, io.EOF) {
				return
			}
			log.Printf("ringbuf read: %v", err)
			continue
		}

		var ev sslEvent
		r := bytes.NewReader(record.RawSample)
		if err := binary.Read(r, binary.LittleEndian, &ev); err != nil {
			log.Printf("decode event: %v", err)
			continue
		}
		if ev.FragCnt == 0 || ev.FragIdx >= ev.FragCnt {
			debugLog("drop invalid fragment pid=%d tid=%d call=%d frag=%d/%d", ev.PID, ev.TID, ev.CallID, ev.FragIdx, ev.FragCnt)
			continue
		}
		n := ev.ChunkLen
		if n > maxChunkPayload {
			n = maxChunkPayload
		}
		if n == 0 {
			debugLog("drop empty fragment pid=%d tid=%d call=%d frag=%d/%d", ev.PID, ev.TID, ev.CallID, ev.FragIdx, ev.FragCnt)
			continue
		}
		payload := append([]byte(nil), ev.Payload[:n]...)

		key := reassemblyKey{PID: ev.PID, TID: ev.TID, CallID: ev.CallID}
		st := reassemblies[key]
		if st == nil {
			st = &reassemblyState{
				origLen:   ev.OrigLen,
				totalLen:  ev.TotalLen,
				truncated: ev.Truncated != 0,
				fragCnt:   ev.FragCnt,
				frags:     make(map[uint32][]byte, ev.FragCnt),
				firstAt:   time.Now(),
			}
			reassemblies[key] = st
		}
		st.lastAt = time.Now()
		if ev.OrigLen > st.origLen {
			st.origLen = ev.OrigLen
		}
		if ev.TotalLen > st.totalLen {
			st.totalLen = ev.TotalLen
		}
		if ev.Truncated != 0 {
			st.truncated = true
		}

		// Deduplicate dual-hook duplicates: same call_id + same fragment index + same bytes.
		if prev, ok := st.frags[ev.FragIdx]; ok {
			if bytes.Equal(prev, payload) {
				debugLog("dedup fragment pid=%d tid=%d call=%d frag=%d hook=%d", ev.PID, ev.TID, ev.CallID, ev.FragIdx, ev.HookType)
				goto maybeCleanup
			}
			// Keep first fragment for deterministic reassembly; record collision for debugging.
			debugLog("fragment collision pid=%d tid=%d call=%d frag=%d old=%d new=%d", ev.PID, ev.TID, ev.CallID, ev.FragIdx, len(prev), len(payload))
			goto maybeCleanup
		}
		st.frags[ev.FragIdx] = payload

		if uint32(len(st.frags)) == st.fragCnt {
			var assembled bytes.Buffer
			for i := uint32(0); i < st.fragCnt; i++ {
				frag, ok := st.frags[i]
				if !ok {
					debugLog("missing fragment after complete-count pid=%d tid=%d call=%d idx=%d", ev.PID, ev.TID, ev.CallID, i)
					goto maybeCleanup
				}
				assembled.Write(frag)
			}
			out := assembled.Bytes()
			if st.totalLen > 0 && uint32(len(out)) > st.totalLen {
				out = out[:st.totalLen]
			}
			log.Printf(
				"pid=%d tid=%d call=%d reassembled_len=%d orig_len=%d captured_len=%d truncated=%t frags=%d payload=%q",
				ev.PID, ev.TID, ev.CallID, len(out), st.origLen, st.totalLen, st.truncated, st.fragCnt, formatPayloadForLog(out),
			)

			recordSSLWrite(ev.HookType, st.truncated, len(out))

			containerID, meta := cw.lookupTargetByPID(ev.PID)
			pkt := PacketEvent{
				Timestamp:    time.Now(),
				PID:          ev.PID,
				TID:          ev.TID,
				CallID:       ev.CallID,
				OrigLen:      st.origLen,
				CapturedLen:  st.totalLen,
				Truncated:    st.truncated,
				HookType:     ev.HookType,
				Payload:      sanitizeUTF8(out),
				ContainerID:  containerID,
				PodName:      meta.podName,
				PodNamespace: meta.podNamespace,
			}
			broadcastPacket(cw.hub, pkt)
			if cw.otel != nil {
				cw.otel.emitSSLWrite(pkt, formatPayloadForLog(out))
			}

			delete(reassemblies, key)
		}

	maybeCleanup:
		if time.Since(lastCleanup) < time.Second {
			continue
		}
		now := time.Now()
		for k, v := range reassemblies {
			if now.Sub(v.lastAt) <= reassemblyTTL {
				continue
			}
			log.Printf("reassembly timeout pid=%d tid=%d call=%d have=%d/%d first_seen_ms=%d", k.PID, k.TID, k.CallID, len(v.frags), v.fragCnt, now.Sub(v.firstAt).Milliseconds())
			recordReassemblyTimeout()
			delete(reassemblies, k)
		}
		lastCleanup = now
	}
}

func sanitizeUTF8(b []byte) string {
	s := string(b)
	if utf8.ValidString(s) {
		return s
	}
	return strings.ToValidUTF8(s, "\uFFFD")
}

func formatPayloadForLog(b []byte) string {
	if logPayloadMaxBytes >= len(b) {
		return sanitizeUTF8(b)
	}
	if logPayloadMaxBytes == 0 {
		return "..."
	}
	return sanitizeUTF8(b[:logPayloadMaxBytes]) + "..."
}

func (cw *containerWatch) scanRunning(ctx context.Context, cli *client.Client) error {
	list, err := cli.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return err
	}
	debugLog("ContainerList: %d entries (all states)", len(list))
	running := 0
	for _, c := range list {
		if c.State == "running" {
			running++
		}
	}
	debugLog("running containers: %d", running)
	for _, c := range list {
		if cw.isSelfContainer(c.ID) {
			continue
		}
		if c.State != "running" {
			continue
		}
		if !cw.labelsMatch(c.Labels) {
			debugLog("scan skip id=%s names=%v (labels do not match filter)", shortID(c.ID), c.Names)
			continue
		}
		debugLog("scan attach candidate id=%s names=%v", shortID(c.ID), c.Names)
		cw.attachContainer(ctx, cli, c.ID)
	}
	return nil
}

func (cw *containerWatch) isSelfContainer(fullID string) bool {
	if cw.selfContainerID == "" {
		return false
	}
	api := strings.TrimPrefix(strings.ToLower(fullID), "sha256:")
	if len(api) < 12 {
		return false
	}
	self := strings.ToLower(cw.selfContainerID)
	if len(self) == 64 {
		if len(api) >= 64 {
			return api[:64] == self
		}
		return false
	}
	if len(self) >= 12 {
		return api[:12] == self[:12]
	}
	return api[:12] == self
}

func (cw *containerWatch) handleDockerEvent(ctx context.Context, cli *client.Client, ev events.Message) {
	if ev.Type != "container" {
		return
	}
	id := ev.Actor.ID
	if id == "" {
		return
	}
	if cw.isSelfContainer(id) {
		return
	}

	switch ev.Action {
	case "start":
		insp, err := cli.ContainerInspect(ctx, id)
		if err != nil {
			log.Printf("container %s: inspect: %v", shortID(id), err)
			return
		}
		if !cw.labelsMatch(insp.Config.Labels) {
			debugLog("start skip id=%s (labels do not match filter)", shortID(id))
			return
		}
		cw.attachContainer(ctx, cli, id)
	case "die", "destroy":
		cw.detachContainer(id)
	default:
		// ignore pause, unpause, etc.
	}
}

func (cw *containerWatch) attachContainer(ctx context.Context, cli *client.Client, containerID string) {
	rootPID, err := waitContainerPID(ctx, cli, containerID)
	if err != nil {
		log.Printf("container %s: wait pid: %v", shortID(containerID), err)
		recordAttachError()
		return
	}
	debugLog("attachContainer id=%s root pid=%d", shortID(containerID), rootPID)
	cw.attachUprobes(ctx, containerID, rootPID, targetMeta{})
}

// attachUprobes discovers libssl (or node fallback) under /proc/<pid>/root and attaches uprobes.
func (cw *containerWatch) attachUprobes(ctx context.Context, containerID string, rootPID int, meta targetMeta) {
	cw.mu.Lock()
	if _, ok := cw.byID[containerID]; ok {
		cw.metaByID[containerID] = meta
		cw.mu.Unlock()
		debugLog("attachUprobes id=%s already attached, skip", shortID(containerID))
		return
	}
	cw.mu.Unlock()

	var lib string
	var discoverErr error
	const maxAttempts = 20
	const delay = 150 * time.Millisecond
	for attempt := 0; attempt < maxAttempts; attempt++ {
		select {
		case <-ctx.Done():
			return
		default:
		}
		lib, discoverErr = discoverLibSSLUnderProcRoot(rootPID)
		if discoverErr == nil && lib != "" {
			break
		}
		debugLog("discoverLibSSL root=%d attempt %d/%d: %v", rootPID, attempt+1, maxAttempts, discoverErr)
		time.Sleep(delay)
	}
	if lib == "" || discoverErr != nil {
		if nodeExe, nodeErr := discoverNodeExecutableUnderProcRoot(rootPID); nodeErr == nil && nodeExe != "" {
			exe, err := link.OpenExecutable(nodeExe)
			if err != nil {
				log.Printf("container %s: open node executable %s: %v", shortID(containerID), nodeExe, err)
				recordAttachError()
				return
			}
			lw, err := exe.Uprobe("SSL_write", cw.objs.ProbeSslWrite, nil)
			if err != nil {
				log.Printf("container %s: uprobe SSL_write on node %s: %v", shortID(containerID), nodeExe, err)
				recordAttachError()
				return
			}
			lex, err := exe.Uprobe("SSL_write_ex", cw.objs.ProbeSslWriteEx, nil)
			if err != nil {
				_ = lw.Close()
				log.Printf("container %s: uprobe SSL_write_ex on node %s: %v", shortID(containerID), nodeExe, err)
				recordAttachError()
				return
			}
			log.Printf("attached SSL_write + SSL_write_ex uprobes on node executable: container=%s exe=%s", shortID(containerID), nodeExe)
			cw.registerAttach(containerID, meta, lw, lex)
			return
		}

		log.Printf("container %s: no libssl.so under /proc/%d/root (and no node executable fallback): %v", shortID(containerID), rootPID, discoverErr)
		recordAttachError()
		return
	}

	exe, err := link.OpenExecutable(lib)
	if err != nil {
		log.Printf("container %s: open %s: %v", shortID(containerID), lib, err)
		recordAttachError()
		return
	}

	lw, err := exe.Uprobe("SSL_write", cw.objs.ProbeSslWrite, nil)
	if err != nil {
		log.Printf("container %s: uprobe SSL_write on %s: %v", shortID(containerID), lib, err)
		recordAttachError()
		return
	}
	lex, err := exe.Uprobe("SSL_write_ex", cw.objs.ProbeSslWriteEx, nil)
	if err != nil {
		_ = lw.Close()
		log.Printf("container %s: uprobe SSL_write_ex on %s: %v", shortID(containerID), lib, err)
		recordAttachError()
		return
	}
	log.Printf("attached SSL_write + SSL_write_ex uprobes (all PIDs using this lib): container=%s lib=%s", shortID(containerID), lib)
	cw.registerAttach(containerID, meta, lw, lex)
}

func (cw *containerWatch) registerAttach(containerID string, meta targetMeta, links ...link.Link) {
	cw.mu.Lock()
	defer cw.mu.Unlock()
	if _, ok := cw.byID[containerID]; ok {
		for _, l := range links {
			_ = l.Close()
		}
		return
	}
	cw.byID[containerID] = &attachSet{links: links, containerID: containerID}
	cw.metaByID[containerID] = meta
	setAttachedTargets(len(cw.byID))
}

// discoverLibSSLUnderProcRoot finds libssl.so* inside the container filesystem via /proc/<pid>/root.
func discoverLibSSLUnderProcRoot(rootPID int) (string, error) {
	procRoot := fmt.Sprintf("/proc/%d/root", rootPID)
	candidates := []string{
		"lib/libssl.so.3",
		"lib64/libssl.so.3",
		"lib/x86_64-linux-gnu/libssl.so.3",
		"lib/aarch64-linux-gnu/libssl.so.3",
		"usr/lib/x86_64-linux-gnu/libssl.so.3",
		"usr/lib/aarch64-linux-gnu/libssl.so.3",
		"usr/lib/libssl.so.3",
		"usr/local/lib/libssl.so.3",
	}
	for _, rel := range candidates {
		p := filepath.Join(procRoot, rel)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}
	searchRoots := []string{
		filepath.Join(procRoot, "usr", "lib"),
		filepath.Join(procRoot, "lib"),
		filepath.Join(procRoot, "lib64"),
		filepath.Join(procRoot, "usr", "local", "lib"),
	}
	for _, dir := range searchRoots {
		var found string
		_ = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			name := filepath.Base(path)
			if strings.HasPrefix(name, "libssl.so") {
				found = path
				return filepath.SkipAll
			}
			return nil
		})
		if found != "" {
			return found, nil
		}
	}
	return "", fmt.Errorf("libssl.so not found under %s/{usr/lib,lib,lib64,usr/local/lib}", procRoot)
}

// discoverNodeExecutableUnderProcRoot finds a likely node binary path for static-OpenSSL fallback.
func discoverNodeExecutableUnderProcRoot(rootPID int) (string, error) {
	procRoot := fmt.Sprintf("/proc/%d/root", rootPID)
	candidates := []string{
		"usr/local/bin/node",
		"usr/bin/node",
		"usr/bin/nodejs",
		"bin/node",
		"bin/nodejs",
	}
	for _, rel := range candidates {
		p := filepath.Join(procRoot, rel)
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
	}

	// Fallback: bounded walk through common roots for custom Node layouts.
	searchRoots := []string{
		filepath.Join(procRoot, "usr"),
		filepath.Join(procRoot, "usr", "local"),
		filepath.Join(procRoot, "bin"),
		filepath.Join(procRoot, "opt"),
	}
	for _, root := range searchRoots {
		var found string
		_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil || info == nil || info.IsDir() {
				return nil
			}
			name := filepath.Base(path)
			if name == "node" || name == "nodejs" {
				found = path
				return filepath.SkipAll
			}
			return nil
		})
		if found != "" {
			return found, nil
		}
	}
	return "", fmt.Errorf("node executable not found under %s/{usr/local/bin,usr/bin,bin,usr,opt}", procRoot)
}

func (cw *containerWatch) detachContainer(containerID string) {
	cw.mu.Lock()
	var toClose []link.Link
	var removed []string
	for id, as := range cw.byID {
		if id == containerID || containerIDsMatch(id, containerID) {
			if as != nil {
				toClose = append(toClose, as.links...)
			}
			removed = append(removed, id)
		}
	}
	for _, id := range removed {
		delete(cw.byID, id)
		delete(cw.metaByID, id)
	}
	n := len(cw.byID)
	cw.mu.Unlock()
	setAttachedTargets(n)
	if len(toClose) == 0 {
		return
	}
	for _, l := range toClose {
		_ = l.Close()
	}
	log.Printf("detached uprobes: container=%s", shortID(containerID))
}

func (cw *containerWatch) detachAll() {
	cw.mu.Lock()
	ids := make([]string, 0, len(cw.byID))
	for id := range cw.byID {
		ids = append(ids, id)
	}
	cw.mu.Unlock()
	for _, id := range ids {
		cw.detachContainer(id)
	}
}

func waitContainerPID(ctx context.Context, cli *client.Client, containerID string) (int, error) {
	const maxAttempts = 50
	var lastErr error
	for i := 0; i < maxAttempts; i++ {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		default:
		}
		insp, err := cli.ContainerInspect(ctx, containerID)
		if err != nil {
			lastErr = err
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if !insp.State.Running {
			return 0, fmt.Errorf("container not running")
		}
		if insp.State.Pid > 0 {
			return insp.State.Pid, nil
		}
		time.Sleep(100 * time.Millisecond)
	}
	if lastErr != nil {
		return 0, fmt.Errorf("no pid after retries: %w", lastErr)
	}
	return 0, fmt.Errorf("no pid after retries")
}

func (cw *containerWatch) lookupTargetByPID(pid uint32) (containerID string, meta targetMeta) {
	cw.mu.Lock()
	defer cw.mu.Unlock()

	if cg, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid)); err == nil {
		s := strings.ToLower(string(cg))
		for id, m := range cw.metaByID {
			needle := strings.ToLower(id)
			if len(needle) > 12 {
				needle = needle[:12]
			}
			if strings.Contains(s, strings.ToLower(id)) || (len(needle) >= 12 && strings.Contains(s, needle)) {
				return id, m
			}
		}
		for id := range cw.byID {
			needle := strings.ToLower(id)
			if len(needle) > 12 {
				needle = needle[:12]
			}
			if strings.Contains(s, strings.ToLower(id)) || (len(needle) >= 12 && strings.Contains(s, needle)) {
				return id, cw.metaByID[id]
			}
		}
	}

	for id, m := range cw.metaByID {
		return id, m
	}
	for id := range cw.byID {
		return id, targetMeta{}
	}
	return "unknown", targetMeta{}
}

func shortID(id string) string {
	if len(id) > 12 {
		return id[:12]
	}
	return id
}
