package main

import "testing"

func TestLocalOnly(t *testing.T) {
	for addr, want := range map[string]bool{
		"127.0.0.1:8080":      true,
		"127.0.0.2:80":        true,
		"[::1]:8080":          true,
		"localhost:8080":      true,
		":8080":               false,
		"0.0.0.0:8080":        false,
		"[::]:8080":           false,
		"10.0.0.5:80":         false,
		"depscan.example:443": false,
		"garbage":             false,
	} {
		if got := localOnly(addr); got != want {
			t.Errorf("localOnly(%q) = %t, want %t", addr, got, want)
		}
	}
}
