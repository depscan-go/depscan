package store

import (
	"bytes"
	"context"
	"sort"
	"sync"
	"time"
)

// Memory keeps scans in this process until it exits.
type Memory struct {
	lim   Limits
	mu    sync.RWMutex
	scans map[string]*Scan
	bytes int64
}

var _ Store = (*Memory)(nil)

// NewMemory returns an empty memory store.
func NewMemory(lim Limits) *Memory {
	return &Memory{lim: lim, scans: make(map[string]*Scan)}
}

func (m *Memory) Save(_ context.Context, s Scan) error {
	if err := check(s); err != nil {
		return err
	}
	// Truncated like Postgres's timestamptz, so both versions agree.
	c := Scan{ID: s.ID, Kind: s.Kind, ScannedAt: s.ScannedAt.UTC().Truncate(time.Microsecond), Record: bytes.Clone(s.Record), Report: bytes.Clone(s.Report)}
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.scans[s.ID]; ok {
		return ErrExists
	}
	m.scans[s.ID] = &c
	m.bytes += size(c.Record, c.Report)
	return nil
}

func (m *Memory) SetReport(_ context.Context, id string, record, report []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	old, ok := m.scans[id]
	if !ok {
		return ErrNotFound
	}
	c := *old
	c.Record, c.Report = bytes.Clone(record), bytes.Clone(report)
	m.bytes += size(c.Record, c.Report) - size(old.Record, old.Report)
	m.scans[id] = &c
	return nil
}

func (m *Memory) Get(_ context.Context, id string) (Scan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.scans[id]
	if !ok || m.lim.expired(s.Kind, s.ScannedAt, time.Now()) {
		return Scan{}, ErrNotFound
	}
	return Scan{ID: s.ID, Kind: s.Kind, ScannedAt: s.ScannedAt, Record: bytes.Clone(s.Record)}, nil
}

func (m *Memory) Report(_ context.Context, id string) ([]byte, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.scans[id]
	if !ok || s.Report == nil || m.lim.expired(s.Kind, s.ScannedAt, time.Now()) {
		return nil, ErrNotFound
	}
	return bytes.Clone(s.Report), nil
}

func (m *Memory) List(_ context.Context, limit int) ([]Scan, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	now := time.Now()
	live := make([]*Scan, 0, len(m.scans))
	for _, s := range m.scans {
		if !m.lim.expired(s.Kind, s.ScannedAt, now) {
			live = append(live, s)
		}
	}
	// Newest first; the ID breaks ties, as in Postgres.
	sort.Slice(live, func(i, j int) bool {
		a, b := live[i], live[j]
		if !a.ScannedAt.Equal(b.ScannedAt) {
			return a.ScannedAt.After(b.ScannedAt)
		}
		return a.ID > b.ID
	})
	if limit > 0 && len(live) > limit {
		live = live[:limit]
	}
	out := make([]Scan, len(live))
	for i, s := range live {
		out[i] = Scan{ID: s.ID, Kind: s.Kind, ScannedAt: s.ScannedAt, Record: bytes.Clone(s.Record)}
	}
	return out, nil
}

func (m *Memory) Prune(_ context.Context, now time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, s := range m.scans {
		if m.lim.expired(s.Kind, s.ScannedAt, now) {
			m.drop(id)
		}
	}
	if m.lim.MaxBytes <= 0 || m.bytes <= m.lim.MaxBytes {
		return nil
	}
	order := make([]*Scan, 0, len(m.scans))
	for _, s := range m.scans {
		order = append(order, s)
	}
	// Uploads before pull request scans, then oldest first.
	sort.Slice(order, func(i, j int) bool {
		a, b := order[i], order[j]
		if a.Kind != b.Kind {
			return a.Kind == Other
		}
		if !a.ScannedAt.Equal(b.ScannedAt) {
			return a.ScannedAt.Before(b.ScannedAt)
		}
		return a.ID < b.ID
	})
	for _, s := range order {
		if m.bytes <= m.lim.TargetBytes {
			break
		}
		m.drop(s.ID)
	}
	return nil
}

// drop deletes one scan. The caller holds m.mu.
func (m *Memory) drop(id string) {
	s := m.scans[id]
	m.bytes -= size(s.Record, s.Report)
	delete(m.scans, id)
}

func (m *Memory) Close() {}
