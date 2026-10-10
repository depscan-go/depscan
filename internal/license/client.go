package license

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/depscan-go/depscan/internal/model"
)

type Client struct {
	http    *http.Client
	baseURL string
	workers int

	mu    sync.Mutex
	cache map[string]string
}

func New() *Client {
	return &Client{
		http:    &http.Client{Timeout: 15 * time.Second},
		baseURL: "https://api.deps.dev",
		workers: 8,
		cache:   make(map[string]string),
	}
}

func NewWithBaseURL(baseURL string) *Client {
	c := New()
	c.baseURL = baseURL
	return c
}

var errNotFound = errors.New("version not found on deps.dev")

type versionResponse struct {
	Licenses []string `json:"licenses"`
}

func systemFor(ecosystem string) (string, bool) {
	switch ecosystem {
	case "Go":
		return "GO", true
	case "npm":
		return "NPM", true
	}
	return "", false
}

func (c *Client) Lookup(ctx context.Context, dep model.Dependency) (string, error) {
	system, ok := systemFor(dep.Ecosystem)
	if !ok {
		return "", nil
	}

	key := system + "/" + dep.Name + "@" + dep.Version
	c.mu.Lock()
	if lic, hit := c.cache[key]; hit {
		c.mu.Unlock()
		return lic, nil
	}
	c.mu.Unlock()

	lic, err := c.fetch(ctx, system, dep)
	if err != nil {
		return "", err
	}

	c.mu.Lock()
	c.cache[key] = lic
	c.mu.Unlock()
	return lic, nil
}

func (c *Client) fetch(ctx context.Context, system string, dep model.Dependency) (string, error) {

	versions := []string{dep.Version}
	if system == "GO" && !strings.HasPrefix(dep.Version, "v") {
		versions = []string{"v" + dep.Version, dep.Version}
	}

	for _, v := range versions {
		lic, err := c.get(ctx, system, dep.Name, v)
		if errors.Is(err, errNotFound) {
			continue
		}
		return lic, err
	}
	return "", nil
}

func (c *Client) get(ctx context.Context, system, name, version string) (string, error) {
	u := fmt.Sprintf("%s/v3/systems/%s/packages/%s/versions/%s",
		c.baseURL, system, escapeSegment(name), escapeSegment(version))

	var lastErr error
	for attempt := 0; attempt < 3; attempt++ {
		if attempt > 0 {
			// Back off 500ms, then 1s, unless the scan is cancelled.
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(attempt) * 500 * time.Millisecond):
			}
		}

		lic, retry, err := c.getOnce(ctx, u)
		if err == nil || !retry {
			return lic, err
		}
		lastErr = err
	}
	return "", lastErr
}

// getOnce does one request. retry is true only for network errors, 429 and 5xx.
func (c *Client) getOnce(ctx context.Context, u string) (lic string, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", false, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return "", true, fmt.Errorf("GET %s: %w", u, err)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	_ = resp.Body.Close() // read-only body: a close error changes nothing
	if err != nil {
		return "", true, err
	}

	switch {
	case resp.StatusCode == http.StatusNotFound:
		return "", false, errNotFound
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return "", true, fmt.Errorf("deps.dev returned %d", resp.StatusCode)
	case resp.StatusCode != http.StatusOK:
		return "", false, fmt.Errorf("deps.dev returned %d", resp.StatusCode)
	}

	var vr versionResponse
	if err := json.Unmarshal(body, &vr); err != nil {
		return "", false, fmt.Errorf("decoding deps.dev response: %w", err)
	}
	return joinLicenses(vr.Licenses), false, nil
}

func joinLicenses(ls []string) string {
	var parts []string
	for _, l := range ls {
		if l = strings.TrimSpace(l); l != "" {
			if len(ls) > 1 && strings.ContainsAny(l, " ") {
				l = "(" + l + ")"
			}
			parts = append(parts, l)
		}
	}
	return strings.Join(parts, " AND ")
}

func escapeSegment(s string) string {
	return strings.ReplaceAll(url.PathEscape(s), "@", "%40")
}

func (c *Client) Enrich(ctx context.Context, deps []model.Dependency) (errs []error) {
	sem := make(chan struct{}, c.workers)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for i := range deps {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			lic, err := c.Lookup(ctx, deps[i])
			if err != nil {
				mu.Lock()
				errs = append(errs, fmt.Errorf("%s@%s: %w", deps[i].Name, deps[i].Version, err))
				mu.Unlock()
				return
			}
			deps[i].License = lic // each goroutine writes only its own index
		}(i)
	}
	wg.Wait()
	return errs
}
