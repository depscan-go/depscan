// Package store keeps scans: each scan's JSON record and, for pull request
// scans, the CycloneDX report exactly as it was hashed. It never parses
// either. Memory keeps them until the process exits; Postgres keeps them in
// a database.
package store

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// Kind decides how long a scan is kept.
type Kind string

const (
	PR    Kind = "pr"    // pull request scans: kept until space runs short
	Other Kind = "other" // dashboard uploads and folder scans: kept 30 days
)

// Scan is one saved scan. Record is the scan's JSON as the API serves it.
// Report is the CycloneDX report exactly as it was hashed and anchored, or nil.
type Scan struct {
	ID        string
	Kind      Kind
	ScannedAt time.Time
	Record    []byte
	Report    []byte
}

var (
	ErrNotFound = errors.New("scan not found")
	ErrExists   = errors.New("a scan with this ID already exists")
)

// Store is where scans are kept.
type Store interface {
	// Save adds a new scan. It returns ErrExists if the ID is taken.
	Save(ctx context.Context, s Scan) error
	// SetReport replaces a saved scan's record and adds its report.
	SetReport(ctx context.Context, id string, record, report []byte) error
	// Get returns a scan with its Record, not its Report.
	Get(ctx context.Context, id string) (Scan, error)
	// Report returns a scan's report, or ErrNotFound if it has none.
	Report(ctx context.Context, id string) ([]byte, error)
	// List returns up to limit scans (all of them if limit <= 0), newest
	// first, with their Records, not their Reports.
	List(ctx context.Context, limit int) ([]Scan, error)
	// Prune applies the retention rules as of now.
	Prune(ctx context.Context, now time.Time) error
	Close()
}

// MB is a megabyte, as Neon counts storage.
const MB = 1_000_000

// Limits are the retention rules. Get, Report and List hide Other scans older
// than OtherMaxAge right away; Prune deletes them. When the stored bytes pass
// MaxBytes, Prune deletes the oldest Other scans, then the oldest PR scans,
// until at most TargetBytes are left. A zero turns its rule off.
type Limits struct {
	OtherMaxAge time.Duration
	MaxBytes    int64
	TargetBytes int64
}

var (
	// PostgresLimits keep Neon's free 1 GB from filling up. The rule counts
	// the bytes we stored; Postgres compresses them on disk.
	PostgresLimits = Limits{OtherMaxAge: 30 * 24 * time.Hour, MaxBytes: 700 * MB, TargetBytes: 600 * MB}
	// MemoryLimits are smaller, because memory scans share the app's 1 GiB.
	MemoryLimits = Limits{OtherMaxAge: 30 * 24 * time.Hour, MaxBytes: 100 * MB, TargetBytes: 80 * MB}
)

// expired says whether a scan is past its age limit at now.
func (l Limits) expired(k Kind, scannedAt, now time.Time) bool {
	return k == Other && l.OtherMaxAge > 0 && now.Sub(scannedAt) > l.OtherMaxAge
}

// check refuses scans no version should keep.
func check(s Scan) error {
	switch {
	case s.ID == "":
		return errors.New("scan has no ID")
	case s.Kind != PR && s.Kind != Other:
		return fmt.Errorf("unknown scan kind %q", s.Kind)
	case s.Record == nil:
		return errors.New("scan has no record")
	}
	return nil
}

// size is what the space rule counts for one scan.
func size(record, report []byte) int64 { return int64(len(record) + len(report)) }
