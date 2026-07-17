package main

import (
	"sync"
	"sync/atomic"
)

const chunkSize = 512

// ChunkPool is a fixed slab of 512-byte buffers for ringbuf fragment storage.
type ChunkPool struct {
	chunks [][chunkSize]byte
	free   chan int
	misses atomic.Uint64
}

func newChunkPool(totalBytes int) *ChunkPool {
	if totalBytes < chunkSize {
		totalBytes = 64 << 20 // 64MiB minimum floor if misconfigured
	}
	n := totalBytes / chunkSize
	if n < 1024 {
		n = 1024
	}
	p := &ChunkPool{
		chunks: make([][chunkSize]byte, n),
		free:   make(chan int, n),
	}
	for i := 0; i < n; i++ {
		p.free <- i
	}
	return p
}

func (p *ChunkPool) Cap() int {
	if p == nil {
		return 0
	}
	return len(p.chunks)
}

func (p *ChunkPool) FreeApprox() int {
	if p == nil {
		return 0
	}
	return len(p.free)
}

// Alloc copies src into a pooled chunk. Returns pool index or -1 if exhausted.
func (p *ChunkPool) Alloc(src []byte) int {
	if p == nil {
		return -1
	}
	select {
	case idx := <-p.free:
		n := len(src)
		if n > chunkSize {
			n = chunkSize
		}
		copy(p.chunks[idx][:n], src[:n])
		if n < chunkSize {
			// clear tail so leftover bytes are not observed on reuse
			for i := n; i < chunkSize; i++ {
				p.chunks[idx][i] = 0
			}
		}
		return idx
	default:
		p.misses.Add(1)
		recordChunkPoolExhausted()
		return -1
	}
}

func (p *ChunkPool) Slice(idx int, n int) []byte {
	if p == nil || idx < 0 || idx >= len(p.chunks) {
		return nil
	}
	if n < 0 {
		n = 0
	}
	if n > chunkSize {
		n = chunkSize
	}
	return p.chunks[idx][:n]
}

func (p *ChunkPool) Release(idx int) {
	if p == nil || idx < 0 || idx >= len(p.chunks) {
		return
	}
	select {
	case p.free <- idx:
	default:
		// pool already full - should not happen if Get/Put balanced
	}
}

func (p *ChunkPool) Misses() uint64 {
	if p == nil {
		return 0
	}
	return p.misses.Load()
}

// fragSlots maps frag index -> pool index (-1 = missing).
type fragSlots struct {
	mu    sync.Mutex
	idxs  []int
	lens  []uint16
	count int
}

func newFragSlots(fragCnt uint32) *fragSlots {
	n := int(fragCnt)
	if n < 0 {
		n = 0
	}
	idxs := make([]int, n)
	lens := make([]uint16, n)
	for i := range idxs {
		idxs[i] = -1
	}
	return &fragSlots{idxs: idxs, lens: lens}
}

func (f *fragSlots) put(fragIdx uint32, poolIdx int, n int) (isNew bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if int(fragIdx) >= len(f.idxs) {
		return false
	}
	if f.idxs[fragIdx] >= 0 {
		return false
	}
	f.idxs[fragIdx] = poolIdx
	f.lens[fragIdx] = uint16(n)
	f.count++
	return true
}

func (f *fragSlots) has(fragIdx uint32) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return int(fragIdx) < len(f.idxs) && f.idxs[fragIdx] >= 0
}

func (f *fragSlots) complete() bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count == len(f.idxs) && len(f.idxs) > 0
}

func (f *fragSlots) releaseAll(pool *ChunkPool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	for i, idx := range f.idxs {
		if idx >= 0 {
			pool.Release(idx)
			f.idxs[i] = -1
		}
	}
	f.count = 0
}

func (f *fragSlots) assemble(pool *ChunkPool, totalLen uint32) []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]byte, 0, totalLen)
	for i, idx := range f.idxs {
		if idx < 0 {
			return nil
		}
		n := int(f.lens[i])
		out = append(out, pool.Slice(idx, n)...)
	}
	if totalLen > 0 && uint32(len(out)) > totalLen {
		out = out[:totalLen]
	}
	return out
}

func (f *fragSlots) haveCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.count
}
