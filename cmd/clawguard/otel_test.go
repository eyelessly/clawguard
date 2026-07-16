package main

import (
	"testing"
)

func TestParseTraceparent(t *testing.T) {
	payload := "POST / HTTP/1.1\r\nHost: example.com\r\ntraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\n\r\nbody"
	tid, sid, ok := parseTraceparent(payload)
	if !ok {
		t.Fatal("expected parse ok")
	}
	if tid.String() != "4bf92f3577b34da6a3ce929d0e0e4736" {
		t.Fatalf("trace id: %s", tid.String())
	}
	if sid.String() != "00f067aa0ba902b7" {
		t.Fatalf("span id: %s", sid.String())
	}
	if _, _, ok := parseTraceparent("no header here"); ok {
		t.Fatal("expected miss")
	}
}

func TestParseAnnotationFilter(t *testing.T) {
	f, err := parseAnnotationFilter("")
	if err != nil || f.key != "clawguard.io/monitor" || f.val != "true" {
		t.Fatalf("default: %+v err=%v", f, err)
	}
	f, err = parseAnnotationFilter("clawguard.io/monitor=yes")
	if err != nil || f.val != "yes" {
		t.Fatalf("custom: %+v err=%v", f, err)
	}
}

func TestDebugUIEnabled(t *testing.T) {
	t.Setenv("CLAWGUARD_DEBUG_UI", "")
	if !debugUIEnabled() {
		t.Fatal("default on")
	}
	t.Setenv("CLAWGUARD_DEBUG_UI", "0")
	if debugUIEnabled() {
		t.Fatal("0 should disable")
	}
}

func TestSplitContainerID(t *testing.T) {
	rt, id := splitContainerID("containerd://abc123def456")
	if rt != "containerd" || id != "abc123def456" {
		t.Fatalf("%s %s", rt, id)
	}
}
