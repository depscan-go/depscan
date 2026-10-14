package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/depscan-go/depscan/internal/store"
)

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

func TestOpenStore(t *testing.T) {
	var logs []string
	logf := func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }

	if s := openStore("", logf); !isMemory(s) {
		t.Errorf("no DATABASE_URL: got %T, want memory", s)
	}
	// Opening never connects: nothing listens on port 1, and that's fine.
	s := openStore("postgres://depscan:hunter2@127.0.0.1:1/depscan?sslmode=disable", logf)
	if pg, ok := s.(*store.Postgres); !ok {
		t.Errorf("a valid URL: got %T, want Postgres", s)
	} else {
		pg.Close()
	}

	logs = nil
	s = openStore("postgres://depscan:hunter2@db.example.com:5432/depscan?sslmode=sometimes", logf)
	if !isMemory(s) {
		t.Errorf("a bad URL: got %T, want memory", s)
	}
	all := strings.Join(logs, "\n")
	if !strings.Contains(all, "store: opening Postgres failed: DATABASE_URL is not a valid connection string") {
		t.Errorf("logs = %q", all)
	}
	for _, part := range []string{"hunter2", "db.example.com", "depscan:", "sometimes"} {
		if strings.Contains(all, part) {
			t.Errorf("the log shows part of the URL (%q): %q", part, all)
		}
	}
}

func isMemory(s store.Store) bool {
	_, ok := s.(*store.Memory)
	return ok
}
