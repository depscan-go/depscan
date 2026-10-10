package httpx_test

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/depscan-go/depscan/internal/httpx"
)

var fast = httpx.Policy{Attempts: 3, BaseDelay: time.Millisecond, MaxDelay: 20 * time.Millisecond}

func get(url string) func(context.Context) (*http.Request, error) {
	return func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	}
}

func server(t *testing.T, calls *int32, steps ...http.HandlerFunc) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := int(atomic.AddInt32(calls, 1))
		if n > len(steps) {
			n = len(steps)
		}
		steps[n-1](w, r)
	}))
}

func status(code int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(code) }
}

func ok(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, body) }
}

func reset(w http.ResponseWriter, r *http.Request) {
	conn, _, err := w.(http.Hijacker).Hijack()
	if err == nil {
		_ = conn.Close()
	}
}

func TestDo_RetriesConnectionResets(t *testing.T) {
	var calls int32
	srv := server(t, &calls, reset, reset, ok("finally"))
	defer srv.Close()

	code, body, err := httpx.Do(context.Background(), srv.Client(), fast, 1<<20, get(srv.URL))
	if err != nil || code != 200 || string(body) != "finally" || atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("got %d %q %v after %d calls; want 200 \"finally\" after 3", code, body, err, atomic.LoadInt32(&calls))
	}
}

func TestDo_RetriesServerErrorsAndRateLimits(t *testing.T) {
	var calls int32
	srv := server(t, &calls, status(503), status(429), ok("ok"))
	defer srv.Close()

	code, _, err := httpx.Do(context.Background(), srv.Client(), fast, 1<<20, get(srv.URL))
	if err != nil || code != 200 || atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("got %d %v after %d calls; want 200 after 3", code, err, atomic.LoadInt32(&calls))
	}
}

func TestDo_DoesNotRetryClientErrors(t *testing.T) {
	for _, code := range []int{400, 401, 403, 404, 422} {
		var calls int32
		srv := server(t, &calls, status(code))
		got, _, err := httpx.Do(context.Background(), srv.Client(), fast, 1<<20, get(srv.URL))
		srv.Close()
		if err != nil || got != code || atomic.LoadInt32(&calls) != 1 {
			t.Errorf("%d: got %d %v after %d calls; want it returned after 1 call", code, got, err, atomic.LoadInt32(&calls))
		}
	}
}

func TestDo_RetriesForbiddenWithRetryAfter(t *testing.T) {
	var calls int32
	limited := func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "60") // capped to MaxDelay, so the test stays fast
		w.WriteHeader(http.StatusForbidden)
	}
	srv := server(t, &calls, limited, ok("ok"))
	defer srv.Close()

	start := time.Now()
	code, _, err := httpx.Do(context.Background(), srv.Client(), fast, 1<<20, get(srv.URL))
	if err != nil || code != 200 || atomic.LoadInt32(&calls) != 2 {
		t.Fatalf("got %d %v after %d calls; want 200 after 2", code, err, atomic.LoadInt32(&calls))
	}
	if time.Since(start) > 2*time.Second {
		t.Error("Retry-After was not capped by MaxDelay")
	}
}

func TestDo_GivesUpAfterAttempts(t *testing.T) {
	var calls int32
	srv := server(t, &calls, status(502))
	defer srv.Close()

	code, _, err := httpx.Do(context.Background(), srv.Client(), fast, 1<<20, get(srv.URL))
	if err != nil || code != 502 || atomic.LoadInt32(&calls) != 3 {
		t.Fatalf("got %d %v after %d calls; want the final 502 after 3", code, err, atomic.LoadInt32(&calls))
	}

	var resets int32
	dead := server(t, &resets, reset)
	defer dead.Close()
	if _, _, err := httpx.Do(context.Background(), dead.Client(), fast, 1<<20, get(dead.URL)); err == nil || !strings.Contains(err.Error(), "after 3 attempts") || atomic.LoadInt32(&resets) != 3 {
		t.Fatalf("got %v after %d calls; want an 'after 3 attempts' error", err, atomic.LoadInt32(&resets))
	}
}

func TestDo_RebuildsRequestBodyEachAttempt(t *testing.T) {
	var calls int32
	var mu sync.Mutex
	var bodies []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		mu.Lock()
		bodies = append(bodies, string(b))
		mu.Unlock()
		if atomic.AddInt32(&calls, 1) == 1 {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	post := func(ctx context.Context) (*http.Request, error) {
		return http.NewRequestWithContext(ctx, http.MethodPost, srv.URL, bytes.NewReader([]byte(`{"q":1}`)))
	}
	if _, _, err := httpx.Do(context.Background(), srv.Client(), fast, 1<<20, post); err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(bodies) != 2 || bodies[0] != `{"q":1}` || bodies[1] != `{"q":1}` {
		t.Errorf("bodies sent = %q, want the full body twice", bodies)
	}
}

func TestDo_StopsWhenContextIsCancelled(t *testing.T) {
	var calls int32
	srv := server(t, &calls, status(503))
	defer srv.Close()

	slow := httpx.Policy{Attempts: 5, BaseDelay: time.Hour, MaxDelay: time.Hour}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	start := time.Now()
	if _, _, err := httpx.Do(ctx, srv.Client(), slow, 1<<20, get(srv.URL)); err == nil {
		t.Fatal("want an error after the context is cancelled")
	}
	if time.Since(start) > 2*time.Second || atomic.LoadInt32(&calls) != 1 {
		t.Errorf("waited %s and made %d calls; want a prompt stop after 1", time.Since(start), atomic.LoadInt32(&calls))
	}
}
