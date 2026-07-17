package pluginv1

import (
	"bytes"
	"testing"
)

func TestFrameRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	req := Request{ID: 7, Method: MethodInfo}
	if err := WriteMessage(&buf, req); err != nil {
		t.Fatal(err)
	}
	var got Request
	if err := ReadMessage(&buf, &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != 7 || got.Method != MethodInfo {
		t.Fatalf("got %+v", got)
	}
}
