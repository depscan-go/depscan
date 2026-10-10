package github

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/depscan-go/depscan/internal/httpx"
)

type Fetcher struct {
	http     *http.Client
	baseURL  string
	token    string
	retry    httpx.Policy
	maxFiles int
	maxBytes int64
}

func NewFetcher(token string) *Fetcher {
	return &Fetcher{
		http:     &http.Client{Timeout: 30 * time.Second},
		baseURL:  "https://api.github.com",
		token:    token,
		retry:    httpx.Default,
		maxFiles: 200,
		maxBytes: 20 << 20,
	}
}

func NewFetcherWithBaseURL(baseURL, token string) *Fetcher {
	f := NewFetcher(token)
	f.baseURL = baseURL
	return f
}

var (
	validRepo = regexp.MustCompile(`^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$`)
	validSHA  = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

var lockfiles = map[string]bool{"go.mod": true, "package-lock.json": true}

type treeResponse struct {
	Truncated bool `json:"truncated"`
	Tree      []struct {
		Path string `json:"path"`
		Type string `json:"type"`
		SHA  string `json:"sha"`
		Size int64  `json:"size"`
	} `json:"tree"`
}

func (f *Fetcher) FetchLockfiles(ctx context.Context, repo, sha, dir string) (int, error) {
	if !validRepo.MatchString(repo) || strings.Contains("/"+repo+"/", "/./") || strings.Contains("/"+repo+"/", "/../") {
		return 0, fmt.Errorf("invalid repository name %q", repo)
	}
	if !validSHA.MatchString(sha) {
		return 0, fmt.Errorf("invalid commit SHA %q", sha)
	}
	var tree treeResponse
	treeURL := fmt.Sprintf("%s/repos/%s/git/trees/%s?recursive=1", f.baseURL, repo, url.PathEscape(sha))
	if err := f.getJSON(ctx, treeURL, &tree); err != nil {
		return 0, fmt.Errorf("listing files of %s@%.7s: %w", repo, sha, err)
	}
	if tree.Truncated {

		return 0, fmt.Errorf("%s@%.7s: file tree too large for one API call (truncated)", repo, sha)
	}

	written := 0
	for _, e := range tree.Tree {
		if e.Type != "blob" || !lockfiles[path.Base(e.Path)] || skipped(e.Path) {
			continue
		}
		if written >= f.maxFiles {
			return written, fmt.Errorf("%s: more than %d lockfiles, stopping", repo, f.maxFiles)
		}
		if e.Size > f.maxBytes {
			return written, fmt.Errorf("%s: %s is %d bytes, over the %d byte limit", repo, e.Path, e.Size, f.maxBytes)
		}
		dst, err := safeJoin(dir, e.Path)
		if err != nil {
			return written, err
		}
		blobURL := fmt.Sprintf("%s/repos/%s/git/blobs/%s", f.baseURL, repo, url.PathEscape(e.SHA))
		if err := f.download(ctx, blobURL, dst); err != nil {
			return written, fmt.Errorf("downloading %s: %w", e.Path, err)
		}
		written++
	}
	return written, nil
}

// skipped matches the folders the local scanner skips too.
func skipped(p string) bool {
	for _, part := range strings.Split(p, "/") {
		if part == "vendor" || part == "node_modules" || part == ".git" {
			return true
		}
	}
	return false
}

func safeJoin(dir, p string) (string, error) {
	clean := path.Clean(p)
	if clean == "." || strings.HasPrefix(clean, "../") || clean == ".." || path.IsAbs(clean) || strings.Contains(clean, ":") || strings.Contains(clean, `\`) {
		return "", fmt.Errorf("refusing unsafe path %q", p)
	}
	return filepath.Join(dir, filepath.FromSlash(clean)), nil
}

func (f *Fetcher) get(ctx context.Context, u, accept string, limit int64) ([]byte, error) {
	status, body, err := httpx.Do(ctx, f.http, f.retry, limit, func(ctx context.Context) (*http.Request, error) {
		return f.newRequest(ctx, u, accept)
	})
	if err != nil {
		return nil, err
	}
	if err := checkStatus(status); err != nil {
		return nil, err
	}
	return body, nil
}

func (f *Fetcher) newRequest(ctx context.Context, u, accept string) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", accept)
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "depscan") // GitHub rejects requests without one
	if f.token != "" {
		req.Header.Set("Authorization", "Bearer "+f.token)
	}
	return req, nil
}

func (f *Fetcher) getJSON(ctx context.Context, u string, v any) error {
	body, err := f.get(ctx, u, "application/vnd.github+json", 50<<20)
	if err != nil {
		return err
	}
	return json.Unmarshal(body, v)
}

func (f *Fetcher) download(ctx context.Context, u, dst string) error {
	body, err := f.get(ctx, u, "application/vnd.github.raw", f.maxBytes)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	return os.WriteFile(dst, body, 0o644)
}

// ErrNotFound covers missing repos and commits, and private repos without a token.
var ErrNotFound = errors.New("not found on GitHub (or private without a token)")

func checkStatus(status int) error {
	switch status {
	case http.StatusOK:
		return nil
	case http.StatusNotFound:
		return ErrNotFound
	case http.StatusForbidden, http.StatusTooManyRequests:
		return fmt.Errorf("GitHub returned %d (rate limited? set GITHUB_TOKEN)", status)
	}
	return fmt.Errorf("GitHub returned %d", status)
}
