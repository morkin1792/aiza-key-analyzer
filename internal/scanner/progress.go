package scanner

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mattn/go-isatty"
)

// progressTracker draws a live "spinner + N/Total complete" line on stderr
// while validateKey runs. Without it the operator sees nothing between the
// discovery banner and the summary block — and the scan can take 30s+ even
// with parallelization. The line is suppressed in Silent or Verbose mode,
// and when stderr isn't a TTY (CI logs, redirected output) so it doesn't
// pollute non-interactive sinks.
type progressTracker struct {
	total     int
	completed atomic.Int64
	stop      chan struct{}
	stopOnce  sync.Once
	enabled   bool
	noun      string // unit shown in the line, e.g. "checks" or "keys"
}

func newProgressTracker(total int) *progressTracker {
	p := &progressTracker{
		total: total,
		stop:  make(chan struct{}),
		noun:  "checks",
	}
	p.enabled = Silent == 0 && !Verbose && isatty.IsTerminal(os.Stderr.Fd())
	return p
}

// MultiKeyProgress is the exported handle main() uses to draw overall
// "N/Total keys" progress on stderr during a multi-key scan. It mirrors the
// per-key progressTracker but stays enabled while Silent==1 — the level
// multi-key runs auto-apply to suppress interleaved per-check output, where we
// still want a single overall progress line.
type MultiKeyProgress struct {
	p *progressTracker
}

// NewMultiKeyProgress builds a key-level progress tracker for `total` keys.
// Enabled only when stderr is a TTY, not Verbose, and output isn't fully
// silenced (Silent < 2).
func NewMultiKeyProgress(total int) *MultiKeyProgress {
	p := &progressTracker{
		total: total,
		stop:  make(chan struct{}),
		noun:  "keys",
	}
	p.enabled = Silent < 2 && !Verbose && isatty.IsTerminal(os.Stderr.Fd())
	return &MultiKeyProgress{p: p}
}

func (m *MultiKeyProgress) Start() { m.p.Start() }
func (m *MultiKeyProgress) Tick()  { m.p.Tick() }
func (m *MultiKeyProgress) Stop()  { m.p.Stop() }

func (p *progressTracker) Start() {
	if !p.enabled {
		return
	}
	go p.run()
}

func (p *progressTracker) Tick() {
	if !p.enabled {
		return
	}
	p.completed.Add(1)
}

// Stop is idempotent — safe to call multiple times.
func (p *progressTracker) Stop() {
	if !p.enabled {
		return
	}
	p.stopOnce.Do(func() {
		close(p.stop)
		// Clear the line so the summary that follows starts clean.
		fmt.Fprint(os.Stderr, "\r\033[K")
	})
}

func (p *progressTracker) run() {
	spinner := []rune{'⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'}
	idx := 0
	ticker := time.NewTicker(120 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-p.stop:
			return
		case <-ticker.C:
			done := p.completed.Load()
			pct := 0
			if p.total > 0 {
				pct = int(done) * 100 / p.total
			}
			// \033[K clears from cursor to end of line; \r returns to start.
			fmt.Fprintf(os.Stderr, "\r\033[K%c scanning… %d/%d %s (%d%%)", spinner[idx], done, p.total, p.noun, pct)
			idx = (idx + 1) % len(spinner)
		}
	}
}
