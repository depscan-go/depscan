package github

import (
	"context"
	"log"
	"os"
	"sync"
	"time"

	"github.com/depscan-go/depscan/internal/model"
)

type Source interface {
	FetchLockfiles(ctx context.Context, repo, sha, dir string) (int, error)
}

type Scanner interface {
	Run(ctx context.Context, path string) (*model.ScanResult, error)
}

type Outcome struct {
	Job       Job
	Files     int
	Result    *model.ScanResult
	Err       error
	StartedAt time.Time
	Duration  time.Duration
	Anchor    *AnchorNote // set by the server when it anchors the scan's report
}

// AnchorNote says where a scan's report was anchored, for the pull request
// comment. Anchoring never changes the verdict.
type AnchorNote struct {
	Digest    string // sha256:<hex> of the CycloneDX report
	Network   string
	TxID      string
	URL       string // block explorer
	Signer    string
	ReportURL string // where to download the report, when the server has a public URL
	Err       string // why anchoring failed, if it did
}

type Queue struct {
	jobs    chan Job
	src     Source
	scanner Scanner
	done    func(Outcome)
	started func(context.Context, Job)
	timeout time.Duration
	wg      sync.WaitGroup
}

// OnStart sets a function called when a worker picks up a job, before any
// file is fetched; the server uses it to mark the commit as pending. Call it
// before Start.
func (q *Queue) OnStart(fn func(context.Context, Job)) { q.started = fn }

func NewQueue(size int, src Source, scanner Scanner, done func(Outcome)) *Queue {
	return &Queue{
		jobs:    make(chan Job, size),
		src:     src,
		scanner: scanner,
		done:    done,
		timeout: 5 * time.Minute,
	}
}

func (q *Queue) Enqueue(j Job) bool {
	select {
	case q.jobs <- j:
		return true
	default:
		return false
	}
}

func (q *Queue) Start(ctx context.Context, n int) {
	for i := 0; i < n; i++ {
		q.wg.Add(1)
		go func() {
			defer q.wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case j := <-q.jobs:
					q.done(q.run(ctx, j))
				}
			}
		}()
	}
}

func (q *Queue) Wait() { q.wg.Wait() }

func (q *Queue) run(parent context.Context, j Job) (out Outcome) {
	out = Outcome{Job: j, StartedAt: time.Now()}
	defer func() { out.Duration = time.Since(out.StartedAt) }()

	ctx, cancel := context.WithTimeout(parent, q.timeout)
	defer cancel()

	if q.started != nil {
		q.started(ctx, j)
	}

	dir, err := os.MkdirTemp("", "depscan-pr-*")
	if err != nil {
		out.Err = err
		return out
	}
	defer func() {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("webhook: removing %s: %v", dir, err)
		}
	}()

	out.Files, err = q.src.FetchLockfiles(ctx, j.HeadRepo, j.HeadSHA, dir)
	if err != nil {
		out.Err = err
		return out
	}
	out.Result, out.Err = q.scanner.Run(ctx, dir)
	return out
}
