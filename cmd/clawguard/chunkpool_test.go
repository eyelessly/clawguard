package main

import (
	"bytes"
	"testing"
)

func TestChunkPoolAllocRelease(t *testing.T) {
	p := newChunkPool(64 * 1024) // 64KiB -> 128 slots
	if p.Cap() < 128 {
		t.Fatalf("cap=%d", p.Cap())
	}
	src := bytes.Repeat([]byte("a"), 100)
	idx := p.Alloc(src)
	if idx < 0 {
		t.Fatal("alloc failed")
	}
	got := p.Slice(idx, 100)
	if !bytes.Equal(got, src) {
		t.Fatalf("slice mismatch")
	}
	p.Release(idx)
	if p.FreeApprox() != p.Cap() {
		t.Fatalf("free=%d cap=%d", p.FreeApprox(), p.Cap())
	}
}

func TestFragSlotsAssemble(t *testing.T) {
	p := newChunkPool(64 * 1024)
	slots := newFragSlots(3)
	parts := [][]byte{[]byte("aaa"), []byte("bbbb"), []byte("cc")}
	for i, part := range parts {
		idx := p.Alloc(part)
		if idx < 0 {
			t.Fatal("alloc")
		}
		if !slots.put(uint32(i), idx, len(part)) {
			t.Fatal("put")
		}
	}
	if !slots.complete() {
		t.Fatal("expected complete")
	}
	out := slots.assemble(p, 9)
	if string(out) != "aaabbbbcc" {
		t.Fatalf("got %q", out)
	}
	slots.releaseAll(p)
	if p.FreeApprox() != p.Cap() {
		t.Fatalf("leaked chunks free=%d", p.FreeApprox())
	}
}

func TestChunkPoolExhausted(t *testing.T) {
	p := newChunkPool(chunkSize * 4)
	cap := p.Cap()
	for i := 0; i < cap; i++ {
		if p.Alloc([]byte("x")) < 0 {
			t.Fatalf("alloc %d/%d failed early", i, cap)
		}
	}
	if p.Alloc([]byte("y")) >= 0 {
		t.Fatal("expected exhaustion")
	}
}
