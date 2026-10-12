package github_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/depscan-go/depscan/internal/github"
	"github.com/depscan-go/depscan/internal/model"
)

// fakeGitHubAPI keeps statuses and issue comments in memory, the way the
// GitHub REST API does, and records every request it served.
type fakeGitHubAPI struct {
	mu       sync.Mutex
	statuses []map[string]string // in arrival order, with "sha" added
	comments []fakeComment
	nextID   int64
	calls    []string
	auth     string
	failWith int           // when set, every status POST answers this code
	delay    time.Duration // slows listing comments, to widen races
}

type fakeComment struct {
	ID   int64  `json:"id"`
	PR   int    `json:"-"`
	Body string `json:"body"`
}

func (f *fakeGitHubAPI) server(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("POST /repos/{owner}/{repo}/statuses/{sha}", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		if f.failWith != 0 {
			w.WriteHeader(f.failWith)
			_, _ = io.WriteString(w, `{"message":"Resource not accessible by integration"}`)
			return
		}
		var body map[string]string
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || r.Header.Get("Content-Type") != "application/json" {
			http.Error(w, "bad body", http.StatusBadRequest)
			return
		}
		body["sha"] = r.PathValue("sha")
		f.mu.Lock()
		f.statuses = append(f.statuses, body)
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{}`)
	})
	mux.HandleFunc("GET /repos/{owner}/{repo}/issues/{pr}/comments", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		time.Sleep(f.delay)
		pr, _ := strconv.Atoi(r.PathValue("pr"))
		page, _ := strconv.Atoi(r.URL.Query().Get("page"))
		per, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
		f.mu.Lock()
		var mine []fakeComment
		for _, c := range f.comments {
			if c.PR == pr {
				mine = append(mine, c)
			}
		}
		f.mu.Unlock()
		lo, hi := (page-1)*per, page*per
		if lo > len(mine) {
			lo = len(mine)
		}
		if hi > len(mine) {
			hi = len(mine)
		}
		_ = json.NewEncoder(w).Encode(mine[lo:hi])
	})
	mux.HandleFunc("POST /repos/{owner}/{repo}/issues/{pr}/comments", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		pr, _ := strconv.Atoi(r.PathValue("pr"))
		var body struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		f.nextID++
		f.comments = append(f.comments, fakeComment{ID: f.nextID, PR: pr, Body: body.Body})
		f.mu.Unlock()
		w.WriteHeader(http.StatusCreated)
		_, _ = io.WriteString(w, `{}`)
	})
	mux.HandleFunc("PATCH /repos/{owner}/{repo}/issues/comments/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.record(r)
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		var body struct{ Body string }
		_ = json.NewDecoder(r.Body).Decode(&body)
		f.mu.Lock()
		defer f.mu.Unlock()
		for i := range f.comments {
			if f.comments[i].ID == id {
				f.comments[i].Body = body.Body
				_, _ = io.WriteString(w, `{}`)
				return
			}
		}
		http.NotFound(w, r)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func (f *fakeGitHubAPI) record(r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, r.Method+" "+r.URL.Path)
	f.auth = r.Header.Get("Authorization")
}

func (f *fakeGitHubAPI) ourComments(pr int) []fakeComment {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []fakeComment
	for _, c := range f.comments {
		if c.PR == pr && strings.HasPrefix(c.Body, github.CommentMarker) {
			out = append(out, c)
		}
	}
	return out
}

func prJob(head string) github.Job {
	return github.Job{Repo: "acme/shop", PR: 7, HeadRepo: "someone/shop", HeadSHA: head, Action: "synchronize"}
}

func blocked() *model.ScanResult {
	crypto := model.Dependency{Ecosystem: "Go", Name: "golang.org/x/crypto", Version: "0.14.0", Direct: true}
	ffmpeg := model.Dependency{Ecosystem: "npm", Name: "ffmpeg-static", Version: "5.2.0", Direct: true}
	gin := model.Dependency{Ecosystem: "Go", Name: "github.com/gin-gonic/gin", Version: "1.9.0", Direct: true}
	return &model.ScanResult{
		Deps: []model.Dependency{crypto, ffmpeg, gin},
		Findings: []model.Finding{
			{Dep: crypto, VulnID: "GHSA-v778-237x-gjrc", Aliases: []string{"CVE-2024-45337"}, Severity: "CRITICAL", Summary: "auth bypass | in `PublicKeyCallback`", FixedVersion: "0.31.0"},
			{Dep: gin, VulnID: "GHSA-2c4m-59x9-fr2g", Severity: "MODERATE", FixedVersion: "1.9.1"},
		},
		Violations: []model.Violation{
			{Kind: "vulnerability", Dep: crypto, ID: "CVE-2024-45337", Reason: "CRITICAL | auth bypass in `PublicKeyCallback`"},
			{Kind: "license", Dep: ffmpeg, Reason: "license denied by policy: GPL-3.0-or-later"},
		},
		Warnings: []model.Violation{{Kind: "vulnerability", Dep: gin, ID: "GHSA-2c4m-59x9-fr2g", Reason: "MODERATE severity"}},
	}
}

func TestPublisher_PendingThenFailureAndOneComment(t *testing.T) {
	api := &fakeGitHubAPI{}
	p := github.NewPublisherWithBaseURL(api.server(t).URL, "tok")
	p.DashboardURL = "https://depscan.example.com/"
	ctx := context.Background()
	j := prJob(sha)

	if err := p.Started(ctx, j); err != nil {
		t.Fatalf("Started: %v", err)
	}
	if err := p.Finished(ctx, github.Outcome{Job: j, Files: 2, Result: blocked()}, "abc123"); err != nil {
		t.Fatalf("Finished: %v", err)
	}

	if len(api.statuses) != 2 {
		t.Fatalf("statuses = %+v, want pending then failure", api.statuses)
	}
	if s := api.statuses[0]; s["state"] != "pending" || s["context"] != "depscan" || s["sha"] != sha {
		t.Errorf("first status = %v", s)
	}
	final := api.statuses[1]
	if final["state"] != "failure" || final["description"] != "Blocked: 2 violations, 1 warning" {
		t.Errorf("final status = %v", final)
	}
	if final["target_url"] != "https://depscan.example.com/#scan/abc123" {
		t.Errorf("target_url = %q", final["target_url"])
	}
	if api.auth != "Bearer tok" {
		t.Errorf("Authorization = %q", api.auth)
	}
	got := api.ourComments(7)
	if len(got) != 1 {
		t.Fatalf("comments = %d, want 1", len(got))
	}
	for _, want := range []string{"blocked by policy", "`0.31.0`", "Replace, or review the license", "[Full result](https://depscan.example.com/#scan/abc123)"} {
		if !strings.Contains(got[0].Body, want) {
			t.Errorf("comment is missing %q:\n%s", want, got[0].Body)
		}
	}
}

func TestPublisher_LaterPushEditsTheSameComment(t *testing.T) {
	api := &fakeGitHubAPI{}
	p := github.NewPublisherWithBaseURL(api.server(t).URL, "tok")
	ctx := context.Background()
	// Someone else's comment comes first; it must be left alone.
	api.comments = append(api.comments, fakeComment{ID: 99, PR: 7, Body: "LGTM"})
	api.nextID = 99

	first, second := prJob(sha), prJob(strings.Repeat("b", 40))
	for _, j := range []github.Job{first, second} {
		_ = p.Started(ctx, j)
	}
	_ = p.Finished(ctx, github.Outcome{Job: second, Result: blocked()}, "")
	clean := &model.ScanResult{Deps: []model.Dependency{{Name: "x"}}}
	third := prJob(strings.Repeat("c", 40))
	_ = p.Started(ctx, third)
	if err := p.Finished(ctx, github.Outcome{Job: third, Result: clean}, ""); err != nil {
		t.Fatal(err)
	}

	got := api.ourComments(7)
	if len(got) != 1 {
		t.Fatalf("depscan comments = %d, want exactly 1", len(got))
	}
	if !strings.Contains(got[0].Body, "passes") || !strings.Contains(got[0].Body, "`ccccccc`") {
		t.Errorf("comment was not updated to the newest result:\n%s", got[0].Body)
	}
	if api.comments[0].Body != "LGTM" {
		t.Error("another comment was changed")
	}
}

func TestPublisher_OlderCommitDoesNotOverwriteComment(t *testing.T) {
	api := &fakeGitHubAPI{}
	p := github.NewPublisherWithBaseURL(api.server(t).URL, "tok")
	ctx := context.Background()
	old, newer := prJob(sha), prJob(strings.Repeat("d", 40))
	_ = p.Started(ctx, old)
	_ = p.Started(ctx, newer)

	if err := p.Finished(ctx, github.Outcome{Job: old, Result: blocked()}, ""); err != nil {
		t.Fatal(err)
	}
	if n := len(api.ourComments(7)); n != 0 {
		t.Errorf("an outdated result wrote %d comment(s)", n)
	}
	last := api.statuses[len(api.statuses)-1]
	if last["sha"] != sha || last["state"] != "failure" {
		t.Errorf("the older commit still needs its own status, got %v", last)
	}
}

func TestPublisher_ScanErrorIsNeverASuccess(t *testing.T) {
	api := &fakeGitHubAPI{}
	p := github.NewPublisherWithBaseURL(api.server(t).URL, "tok")
	j := prJob(sha)
	o := github.Outcome{Job: j, Err: errors.New("osv.dev: after 3 attempts: 503")}
	if err := p.Finished(context.Background(), o, ""); err != nil {
		t.Fatal(err)
	}
	if s := api.statuses[0]; s["state"] != "error" || !strings.Contains(s["description"], "503") {
		t.Errorf("status = %v", s)
	}
	c := api.ourComments(7)
	if len(c) != 1 || !strings.Contains(c[0].Body, "could not finish") {
		t.Errorf("comment = %+v", c)
	}
}

func TestPublisher_StatusOnly(t *testing.T) {
	api := &fakeGitHubAPI{}
	p := github.NewPublisherWithBaseURL(api.server(t).URL, "tok")
	p.Comments = false
	if err := p.Finished(context.Background(), github.Outcome{Job: prJob(sha), Result: blocked()}, ""); err != nil {
		t.Fatal(err)
	}
	for _, c := range api.calls {
		if strings.Contains(c, "/comments") {
			t.Errorf("status-only mode touched comments: %s", c)
		}
	}
}

func TestPublisher_ForbiddenSaysWhichPermission(t *testing.T) {
	api := &fakeGitHubAPI{failWith: http.StatusForbidden}
	p := github.NewPublisherWithBaseURL(api.server(t).URL, "tok")
	err := p.Started(context.Background(), prJob(sha))
	if err == nil || !strings.Contains(err.Error(), "write access to commit statuses") {
		t.Errorf("err = %v", err)
	}
}

func TestPublisher_RejectsUnsafeTargets(t *testing.T) {
	api := &fakeGitHubAPI{}
	p := github.NewPublisherWithBaseURL(api.server(t).URL, "tok")
	j := prJob(sha)
	j.Repo = "../../admin"
	if err := p.Started(context.Background(), j); err == nil {
		t.Error("a malformed repository name must not reach the API")
	}
	j = prJob("HEAD")
	if err := p.Started(context.Background(), j); err == nil {
		t.Error("a malformed SHA must not reach the API")
	}
	if len(api.calls) != 0 {
		t.Errorf("calls = %v", api.calls)
	}
}

func TestPublisher_FindsItsCommentOnALaterPage(t *testing.T) {
	api := &fakeGitHubAPI{}
	for i := 1; i <= 150; i++ {
		api.comments = append(api.comments, fakeComment{ID: int64(i), PR: 7, Body: "chatter"})
	}
	api.comments = append(api.comments, fakeComment{ID: 151, PR: 7, Body: github.CommentMarker + "\nold"})
	api.nextID = 151
	p := github.NewPublisherWithBaseURL(api.server(t).URL, "tok")
	if err := p.Finished(context.Background(), github.Outcome{Job: prJob(sha), Result: blocked()}, ""); err != nil {
		t.Fatal(err)
	}
	got := api.ourComments(7)
	if len(got) != 1 || got[0].ID != 151 || strings.HasSuffix(got[0].Body, "old") {
		t.Errorf("comments = %+v", got)
	}
}

func TestPublisher_ConcurrentFinishesKeepOneComment(t *testing.T) {
	api := &fakeGitHubAPI{delay: 30 * time.Millisecond}
	p := github.NewPublisherWithBaseURL(api.server(t).URL, "tok")
	j := prJob(sha)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = p.Finished(context.Background(), github.Outcome{Job: j, Result: blocked()}, "")
		}()
	}
	wg.Wait()
	if n := len(api.ourComments(7)); n != 1 {
		t.Errorf("comments = %d, want 1", n)
	}
}

func TestSummary(t *testing.T) {
	many := &model.ScanResult{Warnings: make([]model.Violation, 2)}
	for _, tc := range []struct {
		o           github.Outcome
		state, desc string
	}{
		{github.Outcome{Result: blocked()}, "failure", "Blocked: 2 violations, 1 warning"},
		{github.Outcome{Result: many}, "success", "Passes with 2 warnings"},
		{github.Outcome{Result: &model.ScanResult{Deps: make([]model.Dependency, 1)}}, "success", "Passes: 1 package, no violations"},
		{github.Outcome{Err: errors.New(strings.Repeat("x", 500))}, "error", ""},
		{github.Outcome{}, "error", "Scan did not finish: no result"},
	} {
		state, desc := github.Summary(tc.o)
		if state != tc.state || (tc.desc != "" && desc != tc.desc) {
			t.Errorf("Summary = %q, %q; want %q, %q", state, desc, tc.state, tc.desc)
		}
		if utf8.RuneCountInString(desc) > 140 {
			t.Errorf("description is %d characters; GitHub allows 140", utf8.RuneCountInString(desc))
		}
	}
}

func TestCommentBody_TableIsSafeAndBounded(t *testing.T) {
	r := blocked()
	for i := 0; i < 40; i++ {
		r.Violations = append(r.Violations, model.Violation{Kind: "vulnerability", Dep: model.Dependency{Name: fmt.Sprintf("pkg%02d", i), Version: "1.0.0"}, ID: "GHSA-x", Reason: "HIGH"})
	}
	body := github.CommentBody(github.Outcome{Job: prJob(sha), Files: 2, Result: r}, "")
	if !strings.HasPrefix(body, github.CommentMarker) {
		t.Error("the comment must start with the marker")
	}
	if !strings.Contains(body, "And 17 more.") {
		t.Errorf("42 violations should list 25 and count 17 more:\n%s", body)
	}
	if !strings.Contains(body, "[GHSA-v778-237x-gjrc](https://osv.dev/vulnerability/GHSA-v778-237x-gjrc) CRITICAL: auth bypass \\| in 'PublicKeyCallback'") {
		t.Errorf("advisory should be linked, with pipes and backticks escaped:\n%s", body)
	}
	if !strings.Contains(body, "`0.31.0`") {
		t.Error("a violation found under an alias should still show its fixed version")
	}
	if strings.Contains(body, "Full result") {
		t.Error("no link should be shown without a dashboard URL")
	}
}

// End to end: a signed webhook delivery goes through the queue, is scanned,
// and the result comes back to the pull request as a status and a comment.
func TestWebhookToPullRequestFeedback(t *testing.T) {
	api := &fakeGitHubAPI{}
	pub := github.NewPublisherWithBaseURL(api.server(t).URL, "tok")
	done := make(chan struct{})
	q := github.NewQueue(4, &fakeSource{}, &fakeScanner{}, func(o github.Outcome) {
		_ = pub.Finished(context.Background(), o, "")
		close(done)
	})
	q.OnStart(func(ctx context.Context, j github.Job) { _ = pub.Started(ctx, j) })
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); q.Wait() }()
	q.Start(ctx, 1)

	wh, err := github.NewWebhookHandler(secret, q.Enqueue)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/webhooks/github", strings.NewReader(prOpened))
	req.Header.Set("X-GitHub-Event", "pull_request")
	req.Header.Set("X-GitHub-Delivery", "d-1")
	req.Header.Set("X-Hub-Signature-256", sign(prOpened))
	rec := httptest.NewRecorder()
	wh.ServeHTTP(rec, req)
	if rec.Code != http.StatusAccepted {
		t.Fatalf("webhook answered %d", rec.Code)
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("scan did not finish within 5s")
	}
	api.mu.Lock()
	defer api.mu.Unlock()
	if len(api.statuses) != 2 || api.statuses[0]["state"] != "pending" || api.statuses[1]["state"] != "success" {
		t.Fatalf("statuses = %+v", api.statuses)
	}
	if api.statuses[1]["sha"] != "0123456789abcdef0123456789abcdef01234567" {
		t.Errorf("status went to %q", api.statuses[1]["sha"])
	}
	if len(api.comments) != 1 || api.comments[0].PR != 42 || !strings.Contains(api.comments[0].Body, "passes") {
		t.Errorf("comments = %+v", api.comments)
	}
	for _, c := range api.calls {
		if !strings.Contains(c, "/repos/depscan-go/depscan/") {
			t.Errorf("results must go to the base repository, not the fork: %s", c)
		}
	}
}
