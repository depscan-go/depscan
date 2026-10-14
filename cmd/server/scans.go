package main

import (
	"net"

	"github.com/depscan-go/depscan/internal/store"
)

// localOnly says whether addr accepts connections from this computer only.
// Only then does GET /scans list every scan.
func localOnly(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// openStore picks where scans are kept: Postgres when DATABASE_URL is set,
// memory otherwise. A URL that can't be parsed falls back to memory, so a bad
// secret never takes the site down, and the log never shows the URL.
func openStore(url string, logf func(string, ...any)) store.Store {
	if url != "" {
		pg, err := store.OpenPostgres(url, store.PostgresLimits)
		if err == nil {
			logf("scans: saved in Postgres")
			return pg
		}
		// err is store.ErrBadURL, whose text is fixed, or a pool setting error.
		logf("store: opening Postgres failed: %v", err)
	}
	logf("scans: kept in memory until the server restarts")
	return store.NewMemory(store.MemoryLimits)
}
