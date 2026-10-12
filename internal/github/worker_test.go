package github_test

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/depscan-go/depscan/internal/github"
	"github.com/depscan-go/depscan/internal/model"
)

type fakeSource struct {
	gotRepo string
	err     error
}

func (f *fakeSource) FetchLockfiles(_ context.Context, repo, _ string, dir string) (int, error) {
	f.gotRepo = repo
	if f.err != nil {
		return 0, f.err
	}
	return 1, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600)
}

type fakeScanner struct{ dir string }

func (f *fakeScanner) Run(_ context.Context, path string) (*model.ScanResult, error) {
	f.dir = path
	if _, err := os.Stat(filepath.Join(path, "go.mod")); err != nil {
		return nil, err
	}
	return &model.ScanResult{Deps: []model.Dependency{{Name: "x"}}}, nil
}

func runOne(t *testing.T, src github.Source, sc github.Scanner, job github.Job) github.Outcome {
	t.Helper()
	got := make(chan github.Outcome, 1)
	q := github.NewQueue(1, src, sc, func(o github.Outcome) { got <- o })

	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); q.Wait() }()
	q.Start(ctx, 1)

	if !q.Enqueue(job) {
		t.Fatal("Enqueue on an empty queue returned false")
	}
	select {
	case o := <-got:
		return o
	case <-time.After(5 * time.Second):
		t.Fatal("no outcome within 5s")
	}
	return github.Outcome{}
}

func TestQueue_FetchesFromHeadRepoAndScans(t *testing.T) {
	src, sc := &fakeSource{}, &fakeScanner{}
	o := runOne(t, src, sc, github.Job{Repo: "base/app", HeadRepo: "fork/app", HeadSHA: sha, PR: 7})

	if o.Err != nil || o.Result == nil || o.Files != 1 {
		t.Fatalf("outcome = %+v", o)
	}
	if src.gotRepo != "fork/app" {
		t.Errorf("fetched from %q, want the head (fork) repo", src.gotRepo)
	}
	if o.Duration <= 0 {
		t.Error("Duration was not recorded")
	}
	if _, err := os.Stat(sc.dir); !os.IsNotExist(err) {
		t.Errorf("temp folder %s was not removed", sc.dir)
	}
}

func TestQueue_ReportsFetchErrors(t *testing.T) {
	o := runOne(t, &fakeSource{err: github.ErrNotFound}, &fakeScanner{}, github.Job{HeadRepo: "a/b", HeadSHA: sha})
	if !errors.Is(o.Err, github.ErrNotFound) || o.Result != nil {
		t.Fatalf("outcome = %+v, want the fetch error", o)
	}
}

func TestQueue_EnqueueDoesNotBlockWhenFull(t *testing.T) {
	q := github.NewQueue(1, &fakeSource{}, &fakeScanner{}, func(github.Outcome) {})
	if !q.Enqueue(github.Job{}) {
		t.Fatal("first job should fit")
	}
	if q.Enqueue(github.Job{}) {
		t.Fatal("second job should be refused, not block")
	}
}

func TestQueue_OnStartRunsBeforeFetching(t *testing.T) {
	var order []string
	src := &orderSource{order: &order}
	got := make(chan github.Outcome, 1)
	q := github.NewQueue(1, src, &fakeScanner{}, func(o github.Outcome) { got <- o })
	q.OnStart(func(_ context.Context, j github.Job) { order = append(order, "start "+j.Repo) })
	ctx, cancel := context.WithCancel(context.Background())
	defer func() { cancel(); q.Wait() }()
	q.Start(ctx, 1)
	q.Enqueue(github.Job{Repo: "acme/shop", HeadRepo: "acme/shop"})
	select {
	case <-got:
	case <-time.After(5 * time.Second):
		t.Fatal("no outcome within 5s")
	}
	if len(order) != 2 || order[0] != "start acme/shop" || order[1] != "fetch" {
		t.Errorf("order = %v, want start then fetch", order)
	}
}

type orderSource struct{ order *[]string }

func (o *orderSource) FetchLockfiles(_ context.Context, _, _ string, dir string) (int, error) {
	*o.order = append(*o.order, "fetch")
	return 1, os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module x\n"), 0o600)
}
