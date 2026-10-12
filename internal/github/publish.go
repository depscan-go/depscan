package github

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/depscan-go/depscan/internal/httpx"
	"github.com/depscan-go/depscan/internal/model"
)

// CommentMarker starts the one comment depscan keeps on a pull request, so a
// later push edits that comment instead of adding another.
const CommentMarker = "<!-- depscan:pr-comment -->"

const (
	statusContext   = "depscan"
	maxDescription  = 140 // GitHub rejects longer status descriptions
	maxCommentRows  = 25  // per table; the rest are counted, not listed
	maxCommentPages = 10  // 1,000 comments is plenty to find our own
	commentTimeout  = 30 * time.Second
)

// Publisher reports scan results back to GitHub: a commit status on the
// pull request's head commit, and one comment on the pull request that is
// updated on every push. It needs a token that can write commit statuses
// and pull request comments on the base repository.
type Publisher struct {
	http    *http.Client
	baseURL string
	token   string
	retry   httpx.Policy

	// Comments turns the pull request comment on or off; statuses are always sent.
	Comments bool
	// DashboardURL, when set, is where the status's "Details" link points,
	// e.g. "https://depscan.example.com". Leave empty for a local server.
	DashboardURL string

	mu     sync.Mutex
	latest map[string]string      // "owner/repo#12" -> head SHA of the newest scan started
	locks  map[string]*sync.Mutex // one comment writer per pull request
}

func NewPublisher(token string) *Publisher {
	return &Publisher{
		http:     &http.Client{Timeout: 20 * time.Second},
		baseURL:  "https://api.github.com",
		token:    token,
		retry:    httpx.Default,
		Comments: true,
		latest:   map[string]string{},
		locks:    map[string]*sync.Mutex{},
	}
}

func NewPublisherWithBaseURL(baseURL, token string) *Publisher {
	p := NewPublisher(token)
	p.baseURL = strings.TrimRight(baseURL, "/")
	return p
}

// Started marks the head commit as being scanned and remembers it as the
// newest scan of the pull request.
func (p *Publisher) Started(ctx context.Context, j Job) error {
	p.mu.Lock()
	p.latest[prKey(j)] = j.HeadSHA
	p.mu.Unlock()
	return p.setStatus(ctx, j, "pending", "Scanning dependencies", "")
}

// Finished posts the final status and updates the pull request comment.
// scanID is the dashboard record of the scan, used for the status link; it
// can be empty. An older commit that finishes after a newer one still gets
// its status, but does not overwrite the comment.
func (p *Publisher) Finished(ctx context.Context, o Outcome, scanID string) error {
	state, desc := Summary(o)
	link := ""
	if p.DashboardURL != "" && scanID != "" {
		link = strings.TrimRight(p.DashboardURL, "/") + "/#scan/" + url.PathEscape(scanID)
	}
	err := p.setStatus(ctx, o.Job, state, desc, link)
	if !p.Comments || o.Job.PR <= 0 {
		return err
	}

	p.mu.Lock()
	newest := p.latest[prKey(o.Job)]
	p.mu.Unlock()
	if newest != "" && newest != o.Job.HeadSHA {
		return err // a newer push is being scanned; its result owns the comment
	}
	if cerr := p.upsertComment(ctx, o.Job, CommentBody(o, link)); cerr != nil {
		if err != nil {
			return fmt.Errorf("%w; comment: %v", err, cerr)
		}
		return cerr
	}
	return err
}

// Summary maps a scan outcome to a commit status state and a short description.
func Summary(o Outcome) (state, description string) {
	if o.Err != nil {
		return "error", clip("Scan did not finish: "+o.Err.Error(), maxDescription)
	}
	r := o.Result
	if r == nil {
		return "error", "Scan did not finish: no result"
	}
	switch v, w := len(r.Violations), len(r.Warnings); {
	case v > 0:
		return "failure", clip(fmt.Sprintf("Blocked: %s, %s", count(v, "violation"), count(w, "warning")), maxDescription)
	case w > 0:
		return "success", clip(fmt.Sprintf("Passes with %s", count(w, "warning")), maxDescription)
	default:
		return "success", fmt.Sprintf("Passes: %s, no violations", count(len(r.Deps), "package"))
	}
}

// CommentBody renders the pull request comment for an outcome. It always
// starts with CommentMarker.
func CommentBody(o Outcome, link string) string {
	var b strings.Builder
	b.WriteString(CommentMarker + "\n")
	sha := o.Job.HeadSHA
	if len(sha) > 7 {
		sha = sha[:7]
	}

	if o.Err != nil {
		b.WriteString("### depscan could not finish the scan\n\n")
		fmt.Fprintf(&b, "Commit `%s`: %s\n\n", sha, cell(o.Err.Error()))
		b.WriteString("The commit status is set to **error**, not success, because a scan with missing data is never reported as a pass. Push again or redeliver the webhook to retry.\n")
		return b.String()
	}
	r := o.Result
	if r == nil {
		r = &model.ScanResult{}
	}
	v, w := len(r.Violations), len(r.Warnings)
	switch {
	case v > 0:
		b.WriteString("### ❌ depscan: blocked by policy\n\n")
	case w > 0:
		b.WriteString("### ⚠️ depscan: passes with warnings\n\n")
	default:
		b.WriteString("### ✅ depscan: passes\n\n")
	}
	direct := 0
	for _, d := range r.Deps {
		if d.Direct {
			direct++
		}
	}
	fmt.Fprintf(&b, "Commit `%s`, %s, %s (%d direct), %s.\n\n",
		sha, count(o.Files, "lockfile"), count(len(r.Deps), "package"), direct, count(len(r.Findings), "advisory"))
	fmt.Fprintf(&b, "| Violations | Warnings | Advisories |\n|---:|---:|---:|\n| %d | %d | %d |\n\n", v, w, len(r.Findings))

	found := findingIndex(r.Findings)
	writeTable(&b, "Blocks the merge", r.Violations, found, true)
	writeTable(&b, "Warnings", r.Warnings, found, v == 0)

	if v > 0 {
		b.WriteString("Upgrade to the versions in **Fix**, push, and depscan scans the new commit. To accept a finding on purpose, add an exception with a reason (and an expiry date) to `policy.yaml`.\n\n")
	}
	if link != "" {
		fmt.Fprintf(&b, "[Full result](%s)\n\n", link)
	}
	b.WriteString("<sub>Updated on every push. Advisories from OSV.dev, licenses from deps.dev.</sub>\n")
	return b.String()
}

func writeTable(b *strings.Builder, title string, list []model.Violation, found map[string]model.Finding, open bool) {
	if len(list) == 0 {
		return
	}
	sorted := append([]model.Violation(nil), list...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].Dep.Name != sorted[j].Dep.Name {
			return sorted[i].Dep.Name < sorted[j].Dep.Name
		}
		return sorted[i].ID < sorted[j].ID
	})
	attr := ""
	if open {
		attr = " open"
	}
	fmt.Fprintf(b, "<details%s>\n<summary><b>%s</b> (%d)</summary>\n\n", attr, title, len(sorted))
	b.WriteString("| Package | Version | Issue | Fix |\n|---|---|---|---|\n")
	for i, x := range sorted {
		if i == maxCommentRows {
			fmt.Fprintf(b, "\nAnd %d more.\n", len(sorted)-maxCommentRows)
			break
		}
		f, ok := found[depKey(x.Dep)+"|"+x.ID]
		issue := cell(x.Reason)
		if ok {
			issue = advisoryLink(f.VulnID)
			if f.Severity != "" {
				issue += " " + cell(f.Severity)
			}
			if f.Summary != "" {
				issue += ": " + cell(clip(f.Summary, 140))
			}
		}
		fix := ""
		switch {
		case ok && f.FixedVersion != "":
			fix = "`" + cell(f.FixedVersion) + "`"
		case x.Kind == "license":
			fix = "Replace, or review the license"
		default:
			fix = "No fixed version yet"
		}
		fmt.Fprintf(b, "| `%s` | `%s` | %s | %s |\n", cell(x.Dep.Name), cell(x.Dep.Version), issue, fix)
	}
	b.WriteString("\n</details>\n\n")
}

// findingIndex finds the advisory behind a violation by its ID or any alias.
func findingIndex(findings []model.Finding) map[string]model.Finding {
	m := make(map[string]model.Finding, len(findings))
	for _, f := range findings {
		m[depKey(f.Dep)+"|"+f.VulnID] = f
		for _, a := range f.Aliases {
			m[depKey(f.Dep)+"|"+a] = f
		}
	}
	return m
}

// advisoryLink links an advisory ID to its OSV.dev page. IDs are letters,
// digits and dashes; anything else is shown as plain text.
func advisoryLink(id string) string {
	if !validAdvisory.MatchString(id) {
		return cell(id)
	}
	return "[" + id + "](https://osv.dev/vulnerability/" + id + ")"
}

var validAdvisory = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]*$`)

func depKey(d model.Dependency) string { return d.Ecosystem + "|" + d.Name + "@" + d.Version }

func prKey(j Job) string { return fmt.Sprintf("%s#%d", strings.ToLower(j.Repo), j.PR) }

// cell keeps text on one table row and stops it from breaking the table or
// the code spans around it.
func cell(s string) string {
	s = strings.Join(strings.Fields(s), " ")
	s = strings.NewReplacer("|", "\\|", "`", "'", "<", "&lt;", ">", "&gt;").Replace(s)
	return clip(s, 300)
}

func clip(s string, n int) string {
	if r := []rune(s); len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}

func count(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	if strings.HasSuffix(word, "y") {
		return fmt.Sprintf("%d %sies", n, strings.TrimSuffix(word, "y"))
	}
	return fmt.Sprintf("%d %ss", n, word)
}

/* ------------------------------------------------------------------ API calls */

func (p *Publisher) setStatus(ctx context.Context, j Job, state, desc, target string) error {
	if !validRepo.MatchString(j.Repo) || !validSHA.MatchString(j.HeadSHA) {
		return fmt.Errorf("refusing to post a status for %q@%q", j.Repo, j.HeadSHA)
	}
	body := map[string]string{"state": state, "context": statusContext, "description": clip(desc, maxDescription)}
	if target != "" {
		body["target_url"] = target
	}
	u := fmt.Sprintf("%s/repos/%s/statuses/%s", p.baseURL, j.Repo, j.HeadSHA)
	_, err := p.send(ctx, http.MethodPost, u, body, p.retry, http.StatusCreated)
	if err != nil {
		return fmt.Errorf("commit status for %s@%.7s: %w", j.Repo, j.HeadSHA, err)
	}
	return nil
}

type issueComment struct {
	ID   int64  `json:"id"`
	Body string `json:"body"`
}

func (p *Publisher) upsertComment(ctx context.Context, j Job, body string) error {
	if !validRepo.MatchString(j.Repo) {
		return fmt.Errorf("invalid repository name %q", j.Repo)
	}
	lock := p.prLock(prKey(j))
	lock.Lock()
	defer lock.Unlock()

	ctx, cancel := context.WithTimeout(ctx, commentTimeout)
	defer cancel()

	id, err := p.findComment(ctx, j)
	if err != nil {
		return err
	}
	payload := map[string]string{"body": body}
	if id != 0 {
		u := fmt.Sprintf("%s/repos/%s/issues/comments/%d", p.baseURL, j.Repo, id)
		_, err = p.send(ctx, http.MethodPatch, u, payload, p.retry, http.StatusOK)
	} else {
		// One attempt only: retrying a POST whose response was lost would
		// leave two comments.
		u := fmt.Sprintf("%s/repos/%s/issues/%d/comments", p.baseURL, j.Repo, j.PR)
		_, err = p.send(ctx, http.MethodPost, u, payload, httpx.Policy{Attempts: 1}, http.StatusCreated)
	}
	if err != nil {
		return fmt.Errorf("pull request comment on %s#%d: %w", j.Repo, j.PR, err)
	}
	return nil
}

func (p *Publisher) findComment(ctx context.Context, j Job) (int64, error) {
	for page := 1; page <= maxCommentPages; page++ {
		u := fmt.Sprintf("%s/repos/%s/issues/%d/comments?per_page=100&page=%d", p.baseURL, j.Repo, j.PR, page)
		data, err := p.send(ctx, http.MethodGet, u, nil, p.retry, http.StatusOK)
		if err != nil {
			return 0, fmt.Errorf("listing comments on %s#%d: %w", j.Repo, j.PR, err)
		}
		var list []issueComment
		if err := json.Unmarshal(data, &list); err != nil {
			return 0, fmt.Errorf("listing comments on %s#%d: %w", j.Repo, j.PR, err)
		}
		for _, c := range list {
			if strings.HasPrefix(c.Body, CommentMarker) {
				return c.ID, nil
			}
		}
		if len(list) < 100 {
			return 0, nil
		}
	}
	return 0, nil
}

func (p *Publisher) prLock(key string) *sync.Mutex {
	p.mu.Lock()
	defer p.mu.Unlock()
	l, ok := p.locks[key]
	if !ok {
		l = &sync.Mutex{}
		p.locks[key] = l
	}
	return l
}

func (p *Publisher) send(ctx context.Context, method, u string, payload any, retry httpx.Policy, want int) ([]byte, error) {
	var raw []byte
	if payload != nil {
		var err error
		if raw, err = json.Marshal(payload); err != nil {
			return nil, err
		}
	}
	status, body, err := httpx.Do(ctx, p.http, retry, 5<<20, func(ctx context.Context) (*http.Request, error) {
		var rd io.Reader // stays a nil interface for requests without a body
		if raw != nil {
			rd = bytes.NewReader(raw)
		}
		req, err := http.NewRequestWithContext(ctx, method, u, rd)
		if err != nil {
			return nil, err
		}
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
		req.Header.Set("User-Agent", "depscan")
		if raw != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		if p.token != "" {
			req.Header.Set("Authorization", "Bearer "+p.token)
		}
		return req, nil
	})
	if err != nil {
		return nil, err
	}
	if status != want {
		return nil, apiError(status, body)
	}
	return body, nil
}

// apiError turns a GitHub error response into a message that says what to fix.
func apiError(status int, body []byte) error {
	var e struct {
		Message string `json:"message"`
	}
	_ = json.Unmarshal(body, &e) // the message is a bonus; the status code is enough
	msg := e.Message
	switch status {
	case http.StatusUnauthorized:
		return fmt.Errorf("GitHub returned 401: GITHUB_TOKEN is missing or expired")
	case http.StatusForbidden, http.StatusNotFound:
		return fmt.Errorf("GitHub returned %d (%s): the token needs write access to commit statuses and pull requests on this repository", status, clip(msg, 120))
	case http.StatusUnprocessableEntity:
		return fmt.Errorf("GitHub returned 422: %s", clip(msg, 200))
	}
	return fmt.Errorf("GitHub returned %d %s", status, clip(msg, 120))
}
