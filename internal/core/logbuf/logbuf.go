// Package logbuf keeps the most recent structured log records in memory so the
// operator console can show them without reading the process stdout.
package logbuf

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

// Entry is one captured log record.
type Entry struct {
	Time    string            `json:"time"`
	Level   string            `json:"level"`
	Message string            `json:"msg"`
	Attrs   map[string]string `json:"attrs,omitempty"`
}

type ring struct {
	mu    sync.Mutex
	items []Entry
	max   int
	sink  func(Entry)
}

// Buffer is an slog.Handler that tees records into a bounded ring buffer and
// forwards them to the wrapped handler unchanged.
type Buffer struct {
	ring   *ring
	base   slog.Handler
	attrs  []slog.Attr
	groups []string
}

// New wraps base and retains the last max records.
func New(max int, base slog.Handler) *Buffer {
	if max <= 0 {
		max = 500
	}
	return &Buffer{ring: &ring{max: max}, base: base}
}

func (b *Buffer) Enabled(ctx context.Context, l slog.Level) bool { return b.base.Enabled(ctx, l) }

func (b *Buffer) Handle(ctx context.Context, r slog.Record) error {
	e := Entry{
		Time:    r.Time.UTC().Format(time.RFC3339),
		Level:   levelName(r.Level),
		Message: r.Message,
		Attrs:   map[string]string{},
	}
	add := func(prefix string, a slog.Attr) {
		if a.Key == "" {
			return
		}
		key := a.Key
		if prefix != "" {
			key = prefix + "." + key
		}
		e.Attrs[key] = a.Value.String()
	}
	for _, a := range b.attrs {
		add("", a)
	}
	prefix := ""
	for i, g := range b.groups {
		if i > 0 {
			prefix += "."
		}
		prefix += g
	}
	r.Attrs(func(a slog.Attr) bool {
		add(prefix, a)
		return true
	})
	if len(e.Attrs) == 0 {
		e.Attrs = nil
	}

	b.ring.mu.Lock()
	b.ring.items = append(b.ring.items, e)
	if over := len(b.ring.items) - b.ring.max; over > 0 {
		b.ring.items = append([]Entry(nil), b.ring.items[over:]...)
	}
	sink := b.ring.sink
	b.ring.mu.Unlock()
	if sink != nil {
		sink(e)
	}

	return b.base.Handle(ctx, r)
}

func (b *Buffer) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return b
	}
	next := &Buffer{ring: b.ring, base: b.base.WithAttrs(attrs), groups: b.groups}
	next.attrs = append(append([]slog.Attr(nil), b.attrs...), attrs...)
	return next
}

func (b *Buffer) WithGroup(name string) slog.Handler {
	if name == "" {
		return b
	}
	return &Buffer{
		ring:   b.ring,
		base:   b.base.WithGroup(name),
		attrs:  b.attrs,
		groups: append(append([]string(nil), b.groups...), name),
	}
}

// SetSink installs a callback invoked for every record (used to persist logs).
// The callback must not block; callers typically forward to a buffered channel.
func (b *Buffer) SetSink(fn func(Entry)) {
	if b == nil || b.ring == nil {
		return
	}
	b.ring.mu.Lock()
	b.ring.sink = fn
	b.ring.mu.Unlock()
}

// Clear drops every in-memory record and returns how many were removed.
func (b *Buffer) Clear() int {
	if b == nil || b.ring == nil {
		return 0
	}
	b.ring.mu.Lock()
	defer b.ring.mu.Unlock()
	n := len(b.ring.items)
	b.ring.items = nil
	return n
}

// Entries returns the retained records newest first. level, when non-empty,
// is a minimum severity (info, warn, error).
func (b *Buffer) Entries(level string, limit int) []Entry {
	if b == nil || b.ring == nil {
		return []Entry{}
	}
	min := levelRank(level)
	b.ring.mu.Lock()
	defer b.ring.mu.Unlock()
	out := make([]Entry, 0, len(b.ring.items))
	for i := len(b.ring.items) - 1; i >= 0; i-- {
		e := b.ring.items[i]
		if levelRank(e.Level) < min {
			continue
		}
		out = append(out, e)
		if limit > 0 && len(out) >= limit {
			break
		}
	}
	return out
}

func levelName(l slog.Level) string {
	switch {
	case l >= slog.LevelError:
		return "ERROR"
	case l >= slog.LevelWarn:
		return "WARN"
	case l >= slog.LevelInfo:
		return "INFO"
	default:
		return "DEBUG"
	}
}

func levelRank(l string) int {
	switch l {
	case "DEBUG", "debug":
		return 0
	case "INFO", "info":
		return 1
	case "WARN", "warn", "WARNING", "warning":
		return 2
	case "ERROR", "error":
		return 3
	}
	return 0
}
