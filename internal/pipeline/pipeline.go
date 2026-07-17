package pipeline

import (
	"context"
	"log"
	"sync"

	"clawguard/internal/event"
	"clawguard/internal/pluginhost"
	"clawguard/internal/version"
)

type dropFunc func(plugin string)

// Pipeline runs sync processors, fans out to sinks, then async (observational) processors.
type Pipeline struct {
	mgr       *pluginhost.Manager
	queueSize int
	onDrop    dropFunc

	mu           sync.Mutex
	sinkQueues   map[string]chan *event.CaptureEvent
	asyncQueues  map[string]chan *event.CaptureEvent
	wg           sync.WaitGroup
	runCtx       context.Context
	cancel       context.CancelFunc
}

func New(mgr *pluginhost.Manager, queueSize int, onDrop dropFunc) *Pipeline {
	if queueSize <= 0 {
		queueSize = 256
	}
	if onDrop == nil {
		onDrop = func(string) {}
	}
	return &Pipeline{
		mgr:         mgr,
		queueSize:   queueSize,
		onDrop:      onDrop,
		sinkQueues:  make(map[string]chan *event.CaptureEvent),
		asyncQueues: make(map[string]chan *event.CaptureEvent),
	}
}

func (p *Pipeline) Start(parent context.Context) {
	p.runCtx, p.cancel = context.WithCancel(parent)
	p.startWorkers()
}

func (p *Pipeline) stopWorkers() {
	p.mu.Lock()
	sinks := p.sinkQueues
	asyncs := p.asyncQueues
	p.sinkQueues = make(map[string]chan *event.CaptureEvent)
	p.asyncQueues = make(map[string]chan *event.CaptureEvent)
	p.mu.Unlock()
	for _, ch := range sinks {
		close(ch)
	}
	for _, ch := range asyncs {
		close(ch)
	}
	p.wg.Wait()
}

func (p *Pipeline) startWorkers() {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx := p.runCtx

	for _, s := range p.mgr.Sinks() {
		name := s.InfoCached().Name
		ch := make(chan *event.CaptureEvent, p.queueSize)
		p.sinkQueues[name] = ch
		client := s
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ev, ok := <-ch:
					if !ok {
						return
					}
					if err := client.Emit(ev); err != nil {
						log.Printf("sink %s emit: %v", name, err)
					}
				}
			}
		}()
	}

	for _, proc := range p.mgr.AsyncProcessors() {
		name := proc.InfoCached().Name
		ch := make(chan *event.CaptureEvent, p.queueSize)
		p.asyncQueues[name] = ch
		client := proc
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case ev, ok := <-ch:
					if !ok {
						return
					}
					out, err := client.Process(ev)
					if err != nil {
						log.Printf("async processor %s: %v", name, err)
						continue
					}
					if out != nil && len(out.Findings) > 0 {
						log.Printf("async processor %s findings=%d pid=%d call_id=%d", name, len(out.Findings), out.PID, out.CallID)
					}
				}
			}
		}()
	}
}

// AfterReload refreshes sink and async-processor workers to match manager.
func (p *Pipeline) AfterReload() {
	p.stopWorkers()
	p.startWorkers()
}

func (p *Pipeline) Close() {
	if p.cancel != nil {
		p.cancel()
	}
	p.stopWorkers()
	p.mgr.Close()
}

// Emit runs sync processors, then enqueues to sinks and async processors (non-blocking).
func (p *Pipeline) Emit(ev *event.CaptureEvent) {
	if ev == nil {
		return
	}
	snap := version.Snapshot()
	ev.ClawguardVersion = snap.Version
	ev.ClawguardCommit = snap.Commit
	ev.ClawguardEdition = snap.Edition
	ev.Plugins = p.mgr.PluginRefs()

	// Sync (mutating) processors - must finish before sinks see the event.
	cur := ev
	for _, proc := range p.mgr.SyncProcessors() {
		out, err := proc.Process(cur)
		if err != nil {
			log.Printf("sync processor %s: %v", proc.InfoCached().Name, err)
			continue
		}
		if out != nil {
			cur = out
		}
	}

	p.mu.Lock()
	sinkQueues := make(map[string]chan *event.CaptureEvent, len(p.sinkQueues))
	for k, v := range p.sinkQueues {
		sinkQueues[k] = v
	}
	asyncQueues := make(map[string]chan *event.CaptureEvent, len(p.asyncQueues))
	for k, v := range p.asyncQueues {
		asyncQueues[k] = v
	}
	p.mu.Unlock()

	for name, ch := range sinkQueues {
		cp := cur.CloneDeep()
		if !trySend(ch, cp) {
			p.onDrop(name)
			log.Printf("sink %s queue full or closed, dropping event", name)
		}
	}

	// Observational processors - side path; must not block capture / sinks.
	for name, ch := range asyncQueues {
		cp := cur.CloneDeep()
		if !trySend(ch, cp) {
			p.onDrop("processor:" + name)
			log.Printf("async processor %s queue full or closed, dropping event", name)
		}
	}
}

func trySend(ch chan *event.CaptureEvent, ev *event.CaptureEvent) (ok bool) {
	defer func() {
		if recover() != nil {
			ok = false
		}
	}()
	select {
	case ch <- ev:
		return true
	default:
		return false
	}
}
