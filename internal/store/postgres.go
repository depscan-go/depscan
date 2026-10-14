package store

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ErrBadURL means DATABASE_URL couldn't be parsed. Its text never includes
// the URL: pgx's own parse errors can echo part of the password.
var ErrBadURL = errors.New("DATABASE_URL is not a valid connection string")

// callTimeout bounds every store call, Neon waking up (about 2.5 s) included.
const callTimeout = 10 * time.Second

var schema = []string{
	`CREATE TABLE IF NOT EXISTS scans (
		id         text PRIMARY KEY,
		kind       text NOT NULL CHECK (kind IN ('pr', 'other')),
		scanned_at timestamptz NOT NULL,
		record     bytea NOT NULL,
		report     bytea,
		size_bytes bigint NOT NULL
	)`,
	`CREATE INDEX IF NOT EXISTS scans_kind_scanned_at ON scans (kind, scanned_at)`,
}

// Postgres keeps scans in a Postgres database, such as Neon.
type Postgres struct {
	pool  *pgxpool.Pool
	lim   Limits
	mu    sync.Mutex
	ready bool // the table exists; checked once per process
}

var _ Store = (*Postgres)(nil)

// OpenPostgres prepares a connection pool. It doesn't connect: the first call
// does, so a database that is asleep or down never stops the server starting.
func OpenPostgres(url string, lim Limits) (*Postgres, error) {
	cfg, err := pgxpool.ParseConfig(url)
	if err != nil {
		return nil, ErrBadURL
	}
	cfg.MaxConns = 4
	cfg.MinConns = 0
	// Idle connections close after a minute, so Neon can go to sleep.
	cfg.MaxConnIdleTime = time.Minute
	cfg.HealthCheckPeriod = 30 * time.Second
	cfg.ConnConfig.ConnectTimeout = callTimeout
	pool, err := pgxpool.NewWithConfig(context.Background(), cfg)
	if err != nil {
		return nil, err
	}
	return &Postgres{pool: pool, lim: lim}, nil
}

// start bounds a call and makes sure the table exists. The first call in a
// process creates it; if that fails, the next call tries again.
func (p *Postgres) start(ctx context.Context) (context.Context, context.CancelFunc, error) {
	ctx, cancel := context.WithTimeout(ctx, callTimeout)
	p.mu.Lock()
	defer p.mu.Unlock()
	if !p.ready {
		for _, stmt := range schema {
			if _, err := p.pool.Exec(ctx, stmt); err != nil {
				cancel()
				return nil, nil, err
			}
		}
		p.ready = true
	}
	return ctx, cancel, nil
}

func (p *Postgres) Save(ctx context.Context, s Scan) error {
	if err := check(s); err != nil {
		return err
	}
	ctx, cancel, err := p.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	_, err = p.pool.Exec(ctx,
		`INSERT INTO scans (id, kind, scanned_at, record, report, size_bytes) VALUES ($1, $2, $3, $4, $5, $6)`,
		s.ID, string(s.Kind), s.ScannedAt, s.Record, s.Report, size(s.Record, s.Report))
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" { // unique_violation
		return ErrExists
	}
	return err
}

func (p *Postgres) SetReport(ctx context.Context, id string, record, report []byte) error {
	ctx, cancel, err := p.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	tag, err := p.pool.Exec(ctx,
		`UPDATE scans SET record = $2, report = $3, size_bytes = $4 WHERE id = $1`,
		id, record, report, size(record, report))
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func (p *Postgres) Get(ctx context.Context, id string) (Scan, error) {
	ctx, cancel, err := p.start(ctx)
	if err != nil {
		return Scan{}, err
	}
	defer cancel()
	var s Scan
	var kind string
	err = p.pool.QueryRow(ctx, `SELECT id, kind, scanned_at, record FROM scans WHERE id = $1`, id).
		Scan(&s.ID, &kind, &s.ScannedAt, &s.Record)
	if errors.Is(err, pgx.ErrNoRows) {
		return Scan{}, ErrNotFound
	}
	if err != nil {
		return Scan{}, err
	}
	s.Kind, s.ScannedAt = Kind(kind), s.ScannedAt.UTC()
	if p.lim.expired(s.Kind, s.ScannedAt, time.Now()) {
		return Scan{}, ErrNotFound
	}
	return s, nil
}

func (p *Postgres) Report(ctx context.Context, id string) ([]byte, error) {
	ctx, cancel, err := p.start(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	var kind string
	var at time.Time
	var report []byte
	err = p.pool.QueryRow(ctx, `SELECT kind, scanned_at, report FROM scans WHERE id = $1`, id).
		Scan(&kind, &at, &report)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	if report == nil || p.lim.expired(Kind(kind), at, time.Now()) {
		return nil, ErrNotFound
	}
	return report, nil
}

func (p *Postgres) List(ctx context.Context, limit int) ([]Scan, error) {
	ctx, cancel, err := p.start(ctx)
	if err != nil {
		return nil, err
	}
	defer cancel()
	var cutoff time.Time // the zero time hides nothing
	if p.lim.OtherMaxAge > 0 {
		cutoff = time.Now().Add(-p.lim.OtherMaxAge)
	}
	var maxRows any // nil is LIMIT NULL: no limit
	if limit > 0 {
		maxRows = limit
	}
	rows, err := p.pool.Query(ctx, `SELECT id, kind, scanned_at, record FROM scans
		WHERE kind = 'pr' OR scanned_at >= $1
		ORDER BY scanned_at DESC, id DESC LIMIT $2`, cutoff, maxRows)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Scan{}
	for rows.Next() {
		var s Scan
		var kind string
		if err := rows.Scan(&s.ID, &kind, &s.ScannedAt, &s.Record); err != nil {
			return nil, err
		}
		s.Kind, s.ScannedAt = Kind(kind), s.ScannedAt.UTC()
		out = append(out, s)
	}
	return out, rows.Err()
}

func (p *Postgres) Prune(ctx context.Context, now time.Time) error {
	ctx, cancel, err := p.start(ctx)
	if err != nil {
		return err
	}
	defer cancel()
	if p.lim.OtherMaxAge > 0 {
		if _, err := p.pool.Exec(ctx, `DELETE FROM scans WHERE kind = 'other' AND scanned_at < $1`, now.Add(-p.lim.OtherMaxAge)); err != nil {
			return err
		}
	}
	if p.lim.MaxBytes <= 0 {
		return nil
	}
	var total int64
	if err := p.pool.QueryRow(ctx, `SELECT coalesce(sum(size_bytes), 0)::bigint FROM scans`).Scan(&total); err != nil {
		return err
	}
	if total <= p.lim.MaxBytes {
		return nil
	}
	// Walk the scans in the order they go (uploads first, then oldest first)
	// and delete each one while the bytes deleted before it don't yet cover
	// the excess. Postgres reuses the freed space; its files don't shrink.
	_, err = p.pool.Exec(ctx, `DELETE FROM scans WHERE id IN (
		SELECT id FROM (
			SELECT id, sum(size_bytes) OVER (ORDER BY kind = 'pr', scanned_at, id ROWS UNBOUNDED PRECEDING) - size_bytes AS before
			FROM scans
		) ordered
		WHERE before < $1)`, total-p.lim.TargetBytes)
	return err
}

func (p *Postgres) Close() { p.pool.Close() }
