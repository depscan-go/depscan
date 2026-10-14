package store_test

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/url"
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/depscan-go/depscan/internal/store"
	"github.com/depscan-go/depscan/internal/store/storetest"
)

// TestPostgres runs the shared suite against DEPSCAN_TEST_DATABASE_URL, a
// throwaway database (CI starts one). Each test gets an empty schema.
func TestPostgres(t *testing.T) {
	base := os.Getenv("DEPSCAN_TEST_DATABASE_URL")
	if base == "" {
		t.Skip("set DEPSCAN_TEST_DATABASE_URL to a throwaway Postgres to run these")
	}
	storetest.Run(t, func(t *testing.T, lim store.Limits) (store.Store, func() store.Store) {
		u := schemaURL(t, base)
		open := func() store.Store {
			s, err := store.OpenPostgres(u, lim)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(s.Close)
			return s
		}
		return open(), open
	})
}

// schemaURL creates an empty schema, drops it when the test ends, and returns
// base with its search_path pointing at it.
func schemaURL(t *testing.T, base string) string {
	t.Helper()
	b := make([]byte, 6)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	schema := "t_" + hex.EncodeToString(b)
	run(t, base, "CREATE SCHEMA "+schema)
	t.Cleanup(func() { run(t, base, "DROP SCHEMA "+schema+" CASCADE") })
	u, err := url.Parse(base)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	return u.String()
}

func run(t *testing.T, base, sql string) {
	t.Helper()
	ctx := context.Background()
	conn, err := pgx.Connect(ctx, base)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(ctx) }()
	if _, err := conn.Exec(ctx, sql); err != nil {
		t.Fatal(err)
	}
}
