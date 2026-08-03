package tigerbeetle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	tb "github.com/tigerbeetle/tigerbeetle-go"
)

// defaultOpTimeout bounds a single hot-path TigerBeetle call. The tigerbeetle-go
// client is not context-cancelable and blocks indefinitely on an unreachable
// cluster, so every call runs under this deadline; exceeding it yields
// ErrUnavailable (a retryable signal) rather than wedging the caller forever. It
// is deliberately generous — a healthy local call completes in well under 5ms — so
// it fires only on a real outage.
const defaultOpTimeout = 5 * time.Second

// Client is the Exchange's handle to a TigerBeetle cluster. It wraps the shared,
// thread-safe tigerbeetle-go client; construct one per process and share it.
//
// It exposes 11 public methods, two of which (Close, Health) are out-of-band
// lifecycle/health calls rather than domain operations — the ledger domain
// surface is 9, within the 10-public-method ceiling (Architecture Rule 1). This
// is a thin, single-responsibility adapter over the tigerbeetle-go client (map
// domain ops to raw account/transfer batches), not a business god-class, so the
// account/hold and transfer-query methods deliberately live on one handle.
type Client struct {
	inner     tb.Client
	opTimeout time.Duration
}

// Option configures a Client at construction.
type Option func(*Client)

// WithOpTimeout overrides the per-call deadline (see defaultOpTimeout). A
// non-positive duration is ignored, leaving the default in force.
func WithOpTimeout(d time.Duration) Option {
	return func(c *Client) {
		if d > 0 {
			c.opTimeout = d
		}
	}
}

// NewClient connects to the cluster at the given addresses (e.g.
// []string{"127.0.0.1:3000"}) and returns a shared handle. The underlying client
// is thread-safe and batches concurrent requests, so callers MUST share one
// instance rather than open one per request.
func NewClient(clusterID uint64, addresses []string, log *slog.Logger, opts ...Option) (*Client, error) {
	inner, err := tb.NewClient(tb.ToUint128(clusterID), addresses)
	if err != nil {
		return nil, fmt.Errorf("tigerbeetle: new client: %w", err)
	}
	c := &Client{inner: inner, opTimeout: defaultOpTimeout}
	for _, opt := range opts {
		opt(c)
	}
	log.Info("tigerbeetle connected", "cluster", clusterID, "addresses", addresses)
	return c, nil
}

// Close releases the client's resources. Call once at shutdown.
func (c *Client) Close() { c.inner.Close() }

// healthProbeAccountID is the account Health looks up. Nothing ever creates it, so
// the lookup answers "no such account" on a live cluster — which is all the probe
// needs. A reserved-looking id keeps it clear that no business meaning attaches.
const healthProbeAccountID = 1

// Health round-trips the cluster and returns nil when it answers within the
// per-call deadline. A timeout or a transport error both surface as
// ErrUnavailable so callers uniformly detect an unreachable cluster.
//
// It looks up an account rather than sending a no-op. Nop() does NOT detect a
// cluster that goes away after the client connected: the client accepts the packet
// and reports success without the cluster having answered, so a Nop-based probe
// reports healthy against a stopped ledger. A lookup has to come back with data
// from the cluster, so it fails when the cluster is gone — which is the whole
// point of a health check. Verified against a real ledger stopped mid-flight.
func (c *Client) Health(ctx context.Context) error {
	_, err := withDeadline(ctx, c.opTimeout, func() ([]tb.Account, error) {
		return c.inner.LookupAccounts([]tb.Uint128{tb.ToUint128(healthProbeAccountID)})
	})
	if err == nil {
		return nil
	}
	if errors.Is(err, ErrUnavailable) {
		return err // deadline path already carries ErrUnavailable
	}
	return fmt.Errorf("%w: %w", ErrUnavailable, err)
}

// withDeadline runs fn under a deadline derived from ctx and timeout. The
// tigerbeetle-go calls take no context and block until the cluster replies, so fn
// runs in a goroutine feeding a size-1 buffered channel and withDeadline selects
// that against the deadline: the caller unblocks when the deadline fires, and the
// buffer lets the still-running goroutine send-and-exit without leaking. On
// deadline expiry the result is ErrUnavailable (wrapping the ctx cause) — the
// retryable "cluster did not answer" signal. All data flows through the channel,
// so there is no shared mutable state and no race. No wall-clock read (ADR-008
// D1): the deadline rides on ctx via context.WithTimeout.
func withDeadline[T any](ctx context.Context, timeout time.Duration, fn func() (T, error)) (T, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := fn()
		done <- result{v: v, err: err}
	}()

	select {
	case r := <-done:
		return r.v, r.err
	case <-ctx.Done():
		var zero T
		return zero, fmt.Errorf("%w: %w", ErrUnavailable, ctx.Err())
	}
}
