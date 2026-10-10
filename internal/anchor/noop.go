package anchor

import (
	"context"
	"fmt"
	"sync"
	"time"
)

type Noop struct {
	now func() time.Time

	mu   sync.Mutex
	seen map[string]bool
}

func NewNoop() *Noop {
	return &Noop{now: time.Now, seen: map[string]bool{}}
}

func (n *Noop) Name() string { return "noop" }

func (n *Noop) Anchor(ctx context.Context, digest string) (Receipt, error) {
	if err := ctx.Err(); err != nil {
		return Receipt{}, err
	}
	d, err := normalize(digest)
	if err != nil {
		return Receipt{}, err
	}

	n.mu.Lock()
	n.seen[d] = true
	n.mu.Unlock()

	return Receipt{
		Digest:     d,
		Backend:    n.Name(),
		AnchoredAt: n.now().UTC().Truncate(time.Second),
	}, nil
}

func (n *Noop) Verify(ctx context.Context, r Receipt) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if r.Backend != n.Name() {
		return fmt.Errorf("receipt is from backend %q, not %q", r.Backend, n.Name())
	}
	d, err := normalize(r.Digest)
	if err != nil {
		return err
	}

	n.mu.Lock()
	ok := n.seen[d]
	n.mu.Unlock()
	if !ok {
		return fmt.Errorf("%w: %s", ErrNotAnchored, d)
	}
	return nil
}
