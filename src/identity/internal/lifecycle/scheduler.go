package lifecycle

import (
	"context"
	"log/slog"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// Rotation defaults. Overlap sits far below Period and far above the publisher's
// document TTL and the consumer's directory cache, so a rotated key set propagates
// while the outgoing key still verifies.
const (
	DefaultPeriod   = 90 * 24 * time.Hour
	DefaultOverlap  = 24 * time.Hour
	DefaultInterval = time.Hour
)

// pruneGrace is how long a key lingers in Vault after its window closes before the
// scheduler erases it. A key is already unpublished and unusable the moment its
// NotAfter passes — a verifier rejects an out-of-window key — so the grace is only a
// margin against clock skew, not a functional delay.
const pruneGrace = time.Hour

// RotationKeyStore is the slice of the KeyStore the scheduler drives: enumerate the
// agents, read one agent's keys, mint a replacement, shorten the outgoing key, and
// erase a retired one. *keystore.VaultStore satisfies it.
type RotationKeyStore interface {
	ListSubdomains(ctx context.Context) ([]string, error)
	List(ctx context.Context, subdomain string) ([]keystore.Key, error)
	Create(ctx context.Context, subdomain string, w keystore.Window) (keystore.Key, error)
	Expire(ctx context.Context, ref keystore.Ref, notAfter time.Time) error
	Destroy(ctx context.Context, ref keystore.Ref) error
}

// SchedulerConfig tunes the rotation cadence. A zero field takes its default.
type SchedulerConfig struct {
	Period   time.Duration // how old the newest key may get before a rotation is due
	Overlap  time.Duration // how long the outgoing key keeps verifying after a rotation
	Interval time.Duration // how often the loop wakes to check every agent
}

// Scheduler rotates every agent's key on a cadence and prunes keys whose window has
// closed. The state it acts on is the keys' own validity windows — there is no
// separate phase record that could drift from them.
type Scheduler struct {
	keys        RotationKeyStore
	invalidator Invalidator
	clock       clock.Clock
	logger      *slog.Logger
	period      time.Duration
	overlap     time.Duration
	interval    time.Duration
}

// NewScheduler wires a Scheduler, applying defaults for any unset cadence field. A nil
// logger falls back to slog.Default.
func NewScheduler(
	keys RotationKeyStore, invalidator Invalidator,
	clk clock.Clock, logger *slog.Logger, cfg SchedulerConfig,
) *Scheduler {
	if logger == nil {
		logger = slog.Default()
	}
	if cfg.Period <= 0 {
		cfg.Period = DefaultPeriod
	}
	if cfg.Overlap <= 0 {
		cfg.Overlap = DefaultOverlap
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultInterval
	}
	return &Scheduler{
		keys:        keys,
		invalidator: invalidator,
		clock:       clk,
		logger:      logger,
		period:      cfg.Period,
		overlap:     cfg.Overlap,
		interval:    cfg.Interval,
	}
}

// Run drives the scheduler until ctx is cancelled: one pass immediately, then one
// every Interval. It never returns an error — a pass that fails for one agent logs and
// moves on, so a single bad agent cannot wedge rotation for the rest.
func (sc *Scheduler) Run(ctx context.Context) {
	ticker := time.NewTicker(sc.interval)
	defer ticker.Stop()
	sc.RunOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sc.RunOnce(ctx)
		}
	}
}

// RunOnce makes one full pass — every agent checked for a due rotation and for keys to
// prune. It is the deterministic entry point the tests drive over a controlled clock,
// and the single-pass primitive Run loops.
func (sc *Scheduler) RunOnce(ctx context.Context) {
	subs, err := sc.keys.ListSubdomains(ctx)
	if err != nil {
		sc.logger.ErrorContext(ctx, "identity.rotation.list_subdomains_failed", "err", err.Error())
		return
	}
	for _, sub := range subs {
		if ctx.Err() != nil {
			return
		}
		sc.rotateIfDue(ctx, sub)
		sc.enforceOverlap(ctx, sub)
		sc.prune(ctx, sub)
	}
}

// rotateIfDue mints an overlapping replacement when the agent's newest key is older
// than the rotation period and invalidates the cache so the new key appears at once.
// Shortening the OUTGOING key is enforceOverlap's job (run every pass), not this
// function's: keeping the two separate is what makes a rotation self-healing — a mint
// that lands but whose shorten fails is repaired on the next pass instead of stranding
// the old key.
func (sc *Scheduler) rotateIfDue(ctx context.Context, subdomain string) {
	keys, err := sc.keys.List(ctx, subdomain)
	if err != nil {
		sc.logger.ErrorContext(ctx, "identity.rotation.list_failed", "subdomain", subdomain, "err", err.Error())
		return
	}
	if len(keys) == 0 {
		return // no key to rotate; a brand-new agent's first key comes from sign-up
	}
	now := sc.clock.Now()
	newest := keys[0] // List is newest-first
	if now.Sub(newest.CreatedAt) < sc.period {
		return // not due yet
	}
	if _, err := sc.keys.Create(ctx, subdomain, keystore.Window{
		NotBefore: now, NotAfter: now.Add(sc.period + sc.overlap),
	}); err != nil {
		sc.logger.ErrorContext(ctx, "identity.rotation.mint_failed", "subdomain", subdomain, "err", err.Error())
		return
	}
	sc.invalidator.Invalidate(subdomain)
	sc.logger.InfoContext(ctx, "identity.rotation.rotated", "subdomain", subdomain)
}

// enforceOverlap caps every OUTGOING key — any key that is not the newest — at
// now+overlap, so an outgoing key stops being served once the overlap drains. It runs
// on EVERY pass and is idempotent: a key already closing within the overlap is left
// alone (Expire only shortens), so a steady-state pass touches nothing. That is what
// makes rotation self-healing — if the shorten failed on the pass that minted the
// replacement (a Vault blip between the two writes), the next pass finds the still-long
// key BY ITS WINDOW (not by list position, which now points at the fresh key) and
// retries, so the old key cannot keep signing for its full original lifetime just
// because one Expire failed.
func (sc *Scheduler) enforceOverlap(ctx context.Context, subdomain string) {
	keys, err := sc.keys.List(ctx, subdomain)
	if err != nil {
		sc.logger.ErrorContext(ctx, "identity.rotation.overlap_list_failed", "subdomain", subdomain, "err", err.Error())
		return
	}
	if len(keys) < 2 {
		return // a lone key is the active one, not an outgoing key to retire
	}
	cutoff := sc.clock.Now().Add(sc.overlap)
	shortened := false
	for _, k := range keys[1:] { // keys[0] is the newest; never shorten the active key
		if !k.Window.NotAfter.After(cutoff) {
			continue // already closing within the overlap
		}
		if err := sc.keys.Expire(ctx, k.Ref, cutoff); err != nil {
			sc.logger.ErrorContext(ctx, "identity.rotation.expire_failed",
				"subdomain", subdomain, "thumbprint", k.Ref.Thumbprint, "err", err.Error())
			continue
		}
		shortened = true
	}
	if shortened {
		sc.invalidator.Invalidate(subdomain)
	}
}

// prune erases keys whose validity window closed at least pruneGrace ago — retired
// keys the directory already stopped serving. It never touches a key still in or
// before its window, so an active or not-yet-valid key is safe.
func (sc *Scheduler) prune(ctx context.Context, subdomain string) {
	keys, err := sc.keys.List(ctx, subdomain)
	if err != nil {
		sc.logger.ErrorContext(ctx, "identity.rotation.prune_list_failed", "subdomain", subdomain, "err", err.Error())
		return
	}
	cutoff := sc.clock.Now().Add(-pruneGrace)
	for _, k := range keys {
		if !k.Window.NotAfter.Before(cutoff) {
			continue // still in, or within grace of, its window
		}
		if err := sc.keys.Destroy(ctx, k.Ref); err != nil {
			sc.logger.ErrorContext(ctx, "identity.rotation.prune_destroy_failed",
				"subdomain", subdomain, "thumbprint", k.Ref.Thumbprint, "err", err.Error())
			continue
		}
		sc.logger.InfoContext(ctx, "identity.rotation.pruned",
			"subdomain", subdomain, "thumbprint", k.Ref.Thumbprint)
	}
}
