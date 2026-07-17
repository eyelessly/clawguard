package config

import "testing"

func TestEffectiveModeDefaults(t *testing.T) {
	cases := []struct {
		name string
		mode string
		want string
	}{
		{"detect", "", "async"},
		{"detect", "sync", "sync"},
		{"mask", "", "sync"},
		{"mask", "async", "async"},
		{"custom", "", "sync"},
	}
	for _, tc := range cases {
		e := PluginEntry{Name: tc.name, Mode: tc.mode}
		if got := e.EffectiveMode(); got != tc.want {
			t.Fatalf("%s mode=%q: got %q want %q", tc.name, tc.mode, got, tc.want)
		}
	}
}
