//go:build integration

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"go.uber.org/goleak"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

// brokerRelaySeed is the deterministic seed label the broker-relay key is
// derived from across every scenario. After the WBA split the RFC 9421 keyid is
// the key's RFC 7638 thumbprint, not this label.
const brokerRelaySeed = "broker-relay.v1"

// TestWellKnownAwareResolver_RevokesThroughMiddleware drives the production
// composition end to end: the real wellKnownAwareResolver (revocation Loader +
// started poller + CompositeResolver) wired into a RFC 9421 verify handler. A
// request signed by a thumbprint the Broker's WBA directory publishes verifies;
// once the Broker revokes that thumbprint, the poller picks it up within a couple
// of intervals and the same signature is rejected. This is the consumer half of
// the revocation feature — the Broker producer side is covered in
// src/broker/internal/transport.
func TestWellKnownAwareResolver_RevokesThroughMiddleware(t *testing.T) {
	now := time.Now().UTC()
	priv, key := testutil.NewSigningKey(brokerRelaySeed, now.Add(-time.Hour), now.Add(1000*time.Hour))
	tp := testutil.MustThumbprintKey(t, key)

	origin := testutil.NewOrigin(nil)
	t.Cleanup(origin.Close)
	// The broker's WBA directory carries the relay key + a directory-level
	// revocation_url the Loader polls.
	f := testutil.WBAFile(key)
	f.RevocationUrl = testutil.Ptr(origin.RevocationURL())
	origin.SetWBA(testutil.MarshalWBA(f))
	// Initial snapshot: nothing revoked, oldest possible as_of.
	origin.SetRevocation(testutil.MarshalRevocation(time.Unix(1000, 0)))

	t.Setenv("EXCHANGE_REVOCATION_POLL_INTERVAL", "150ms")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	// http.DefaultClient, not the guarded client: the origin is a loopback
	// httptest server the production guard would (correctly) refuse.
	resolver := wellKnownAwareResolver(ctx, origin.URL, helpers.NewStaticKeyResolver(nil), http.DefaultClient, slog.Default())

	srv := newHTTPSigServer(t, resolver)

	// Active, unrevoked thumbprint → the signature verifies (200).
	if status := signedDiscoverStatus(t, srv, tp, priv); status != http.StatusOK {
		t.Fatalf("active key: status = %d, want 200", status)
	}

	// Revoke the thumbprint with a strictly-newer snapshot; the poller refreshes
	// and the same signed call is rejected within a few poll intervals.
	origin.SetRevocation(testutil.MarshalRevocation(time.Unix(2000, 0), tp))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if status := signedDiscoverStatus(t, srv, tp, priv); status == http.StatusUnauthorized {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked key still verifying after the poll deadline")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestWellKnownAwareResolver_RevokedKeyOverridesFallthroughDelegate pins the
// revocation-vs-fallthrough PRECEDENCE explicitly: the revoked thumbprint is
// ALSO resolvable by the composite's fall-through delegate (in production the
// per-agent well-known resolver; here an injected fixed-map test resolver), and
// the revocation verdict must win — the composite halts on the authoritative
// REVOKED answer before the later delegate can re-admit the key. Without this
// case the precedence is only inferred from construction order; a resolver
// reordering that consulted the fall-through delegate first would keep every
// still-published key alive forever after revocation and no other test would
// notice.
func TestWellKnownAwareResolver_RevokedKeyOverridesFallthroughDelegate(t *testing.T) {
	now := time.Now().UTC()
	priv, key := testutil.NewSigningKey(brokerRelaySeed, now.Add(-time.Hour), now.Add(1000*time.Hour))
	tp := testutil.MustThumbprintKey(t, key)
	pub, err := rampwellknown.PublicKey(key)
	if err != nil {
		t.Fatalf("derive pubkey: %v", err)
	}
	// The SAME thumbprint the broker will revoke is resolvable by the
	// fall-through delegate — the delegate that must NOT get the last word.
	fallthroughDelegate := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{tp: pub})

	origin := testutil.NewOrigin(nil)
	t.Cleanup(origin.Close)
	f := testutil.WBAFile(key)
	f.RevocationUrl = testutil.Ptr(origin.RevocationURL())
	origin.SetWBA(testutil.MarshalWBA(f))
	origin.SetRevocation(testutil.MarshalRevocation(time.Unix(1000, 0)))

	t.Setenv("EXCHANGE_REVOCATION_POLL_INTERVAL", "150ms")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	resolver := wellKnownAwareResolver(ctx, origin.URL, fallthroughDelegate, http.DefaultClient, slog.Default())
	srv := newHTTPSigServer(t, resolver)

	// Active + resolvable by the fall-through delegate: verifies.
	if status := signedDiscoverStatus(t, srv, tp, priv); status != http.StatusOK {
		t.Fatalf("active fall-through-resolvable key: status = %d, want 200", status)
	}

	// Revoke the thumbprint: the rejection must land even though the
	// fall-through delegate still resolves it (401, no re-admission).
	origin.SetRevocation(testutil.MarshalRevocation(time.Unix(2000, 0), tp))
	deadline := time.Now().Add(5 * time.Second)
	for {
		if status := signedDiscoverStatus(t, srv, tp, priv); status == http.StatusUnauthorized {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("revoked fall-through-resolvable key still verifying after the poll deadline")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// TestWellKnownAwareResolver_ExpiredWindowRejectsDespiteFallthroughDelegate
// pins the second authoritative negative beside revocation: a key whose
// published validity window has ENDED. The directory still lists the key and
// the fall-through delegate still resolves the same thumbprint, so the only
// thing standing between a lapsed key and a 200 is the window verdict —
// resolvers.ErrKeyExpired halting the composite (keyresolver.go maps it as
// authoritative, never a fall-through miss). A refactor that translated the
// expired verdict into a plain unknown-key miss would let the fall-through
// delegate re-admit the key, and before this test nothing would have noticed.
// The published window is the only automatic expiry a verifier gets on a
// rotated-out key it still holds in a stale cached directory.
func TestWellKnownAwareResolver_ExpiredWindowRejectsDespiteFallthroughDelegate(t *testing.T) {
	now := time.Now().UTC()
	// The window ended an hour ago: [now - 1000h, now - 1h).
	priv, key := testutil.NewSigningKey(brokerRelaySeed, now.Add(-1000*time.Hour), now.Add(-time.Hour))
	tp := testutil.MustThumbprintKey(t, key)
	pub, err := rampwellknown.PublicKey(key)
	if err != nil {
		t.Fatalf("derive pubkey: %v", err)
	}
	// The SAME thumbprint stays resolvable by the fall-through delegate — the
	// delegate that must not get the last word on a lapsed key.
	fallthroughDelegate := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{tp: pub})

	origin := testutil.NewOrigin(nil)
	t.Cleanup(origin.Close)
	f := testutil.WBAFile(key)
	f.RevocationUrl = testutil.Ptr(origin.RevocationURL())
	origin.SetWBA(testutil.MarshalWBA(f))
	// Nothing is revoked: the rejection below can come only from the window.
	origin.SetRevocation(testutil.MarshalRevocation(time.Unix(1000, 0)))

	t.Setenv("EXCHANGE_REVOCATION_POLL_INTERVAL", "150ms")

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	resolver := wellKnownAwareResolver(ctx, origin.URL, fallthroughDelegate, http.DefaultClient, slog.Default())
	srv := newHTTPSigServer(t, resolver)

	// The window verdict is synchronous at resolve time — no poller wait.
	if status := signedDiscoverStatus(t, srv, tp, priv); status != http.StatusUnauthorized {
		t.Fatalf("expired-window key resolvable by the fall-through delegate: status = %d, want 401", status)
	}
}

// TestWellKnownAwareResolver_FailsClosedOnFetchFailure pins the fail-closed
// boundary: when the Broker WBA directory is the revocation authority but is
// unreachable/malformed, a thumbprint that the composite's fall-through
// delegate resolves must NOT keep verifying — we cannot prove it is un-revoked,
// so we reject. The contrast case proves the distinction the fix turns on: a
// thumbprint genuinely absent from a *successfully fetched* directory
// (ErrKeyUnknown) is allowed to fall through to the later delegate, because the
// directory is authoritative about the keys it lists, not about a key it never
// carried.
func TestWellKnownAwareResolver_FailsClosedOnFetchFailure(t *testing.T) {
	now := time.Now().UTC()
	priv, key := testutil.NewSigningKey(brokerRelaySeed, now.Add(-time.Hour), now.Add(1000*time.Hour))
	tp := testutil.MustThumbprintKey(t, key)
	pub, err := rampwellknown.PublicKey(key)
	if err != nil {
		t.Fatalf("derive pubkey: %v", err)
	}
	// The fall-through delegate resolves the thumbprint in both sub-cases — the
	// question is only whether the revocation channel's verdict lets it through.
	fallthroughDelegate := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{tp: pub})

	t.Run("fetch failure fails closed despite a resolving fall-through delegate", func(t *testing.T) {
		origin := testutil.NewOrigin(nil)
		t.Cleanup(origin.Close)
		origin.SetWBAStatus(http.StatusInternalServerError) // every WBA lookup → ErrFetch

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		resolver := wellKnownAwareResolver(ctx, origin.URL, fallthroughDelegate, http.DefaultClient, slog.Default())
		srv := newHTTPSigServer(t, resolver)

		if status := signedDiscoverStatus(t, srv, tp, priv); status != http.StatusUnauthorized {
			t.Fatalf("unreachable WBA directory: status = %d, want 401 (fail closed)", status)
		}
	})

	t.Run("thumbprint absent from fetched directory falls through", func(t *testing.T) {
		origin := testutil.NewOrigin(nil)
		t.Cleanup(origin.Close)
		// A valid WBA directory that lists a DIFFERENT key: the lookup is
		// ErrKeyUnknown (fetched + parsed, thumbprint simply not present), which
		// must fall through to the later delegate.
		_, otherKey := testutil.NewSigningKey("other.v1", now.Add(-time.Hour), now.Add(1000*time.Hour))
		origin.SetWBA(testutil.MarshalWBA(testutil.WBAFile(otherKey)))

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		resolver := wellKnownAwareResolver(ctx, origin.URL, fallthroughDelegate, http.DefaultClient, slog.Default())
		srv := newHTTPSigServer(t, resolver)

		if status := signedDiscoverStatus(t, srv, tp, priv); status != http.StatusOK {
			t.Fatalf("thumbprint absent from directory: status = %d, want 200 (fall through)", status)
		}
	})
}

// TestWellKnownAwareResolver_RevokedFallthroughOnlyKeyRejected pins the fix for
// the directory-absent revocation bypass: a thumbprint the broker directory
// does NOT list but that IS present in the broker's revocation list must be
// rejected — even though the composite's fall-through delegate still resolves
// it. Without the fix the broker resolver reports ErrKeyUnknown (not a
// directory key) and the composite falls through to the later delegate, serving
// a revoked key. The contrast case (thumbprint absent AND not revoked → falls
// through) is covered by TestWellKnownAwareResolver_FailsClosedOnFetchFailure.
func TestWellKnownAwareResolver_RevokedFallthroughOnlyKeyRejected(t *testing.T) {
	now := time.Now().UTC()
	priv, key := testutil.NewSigningKey("directory-absent.v1", now.Add(-time.Hour), now.Add(1000*time.Hour))
	tp := testutil.MustThumbprintKey(t, key)
	pub, err := rampwellknown.PublicKey(key)
	if err != nil {
		t.Fatalf("derive pubkey: %v", err)
	}
	// The fall-through delegate resolves the thumbprint — the question is only
	// whether the revocation channel still rejects it.
	fallthroughDelegate := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{tp: pub})

	origin := testutil.NewOrigin(nil)
	t.Cleanup(origin.Close)
	// The broker directory lists a DIFFERENT key (so tp is ErrKeyUnknown at the
	// directory) but its revocation list revokes tp.
	_, otherKey := testutil.NewSigningKey("other.v1", now.Add(-time.Hour), now.Add(1000*time.Hour))
	f := testutil.WBAFile(otherKey)
	f.RevocationUrl = testutil.Ptr(origin.RevocationURL())
	origin.SetWBA(testutil.MarshalWBA(f))
	origin.SetRevocation(testutil.MarshalRevocation(time.Unix(2000, 0), tp))

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	resolver := wellKnownAwareResolver(ctx, origin.URL, fallthroughDelegate, http.DefaultClient, slog.Default())
	srv := newHTTPSigServer(t, resolver)

	if status := signedDiscoverStatus(t, srv, tp, priv); status != http.StatusUnauthorized {
		t.Fatalf("revoked directory-absent key: status = %d, want 401 (revocation must gate the fall-through delegate)", status)
	}
}

// The four cases below are SDK-parity guards: the revocation/SSRF
// anti-amplification controls now live wholly inside the pinned SDK
// resolvers.WBAKeyResolver, and these tests prove each control survives the app
// wiring (wellKnownAwareResolver → RFC 9421 verify), not only inside the SDK's
// own unit tests. There is NO production change behind them — each is expected to
// PASS on the current pin and would fail only if a future SDK bump silently
// dropped that control.

// TestWellKnownAwareResolver_DebouncesUnknownThumbprintBurst pins control (1),
// the per-host sync-debounce. The key resolver runs BEFORE the ed25519 check and
// the directory host is the caller-supplied Signature-Agent, so an
// unauthenticated caller presenting unknown thumbprints could otherwise drive one
// outbound directory GET per thumbprint (reflection/amplification + self-DoS). A
// burst of distinct unknown thumbprints for one host inside a single SyncDebounce
// window must be rejected AND must trigger at most one forced directory refresh.
func TestWellKnownAwareResolver_DebouncesUnknownThumbprintBurst(t *testing.T) {
	now := time.Now().UTC()
	priv, key := testutil.NewSigningKey(brokerRelaySeed, now.Add(-time.Hour), now.Add(1000*time.Hour))
	tp := testutil.MustThumbprintKey(t, key)

	origin := testutil.NewOrigin(nil)
	t.Cleanup(origin.Close)
	origin.SetWBA(testutil.MarshalWBA(testutil.WBAFile(key)))

	srv := startRevocationResolverServer(t, origin.URL)

	// Warm the TTL directory cache with one KNOWN lookup: this fetch fills the
	// SDK's dirCache (WBAHits == 1) WITHOUT touching the unknown-thumbprint sync
	// debounce, so every later WBAHits delta is attributable only to the
	// force-refresh path the debounce gates.
	if status := signedDiscoverStatus(t, srv, tp, priv); status != http.StatusOK {
		t.Fatalf("warm known key: status = %d, want 200", status)
	}
	base := origin.WBAHits()

	// Burst of DISTINCT unknown thumbprints for the same directory host, all
	// inside one SyncDebounce window (SDK default 5s; the burst runs in ms). Each
	// is rejected because it is not in the directory.
	const burst = 4
	for i := range burst {
		uPriv, uKey := testutil.NewSigningKey(
			fmt.Sprintf("unknown-%d.v1", i), now.Add(-time.Hour), now.Add(1000*time.Hour))
		utp := testutil.MustThumbprintKey(t, uKey)
		if status := signedDiscoverStatus(t, srv, utp, uPriv); status != http.StatusUnauthorized {
			t.Fatalf("unknown thumbprint #%d: status = %d, want 401", i, status)
		}
	}

	// The debounce admits at most ONE forced directory refresh per window per
	// host: N unknown lookups drive <= 1 additional WBA fetch, not N.
	if delta := origin.WBAHits() - base; delta > 1 {
		t.Fatalf("WBA directory fetched %d extra times across the unknown burst, want <= 1 (sync debounce)", delta)
	}
}

// TestWellKnownAwareResolver_SkipsCrossHostRevocationURL pins control (2), the
// host-anchored revocation_url gate. A WBA directory that names a revocation_url
// on a DIFFERENT host would otherwise steer the poller at an arbitrary target
// every cadence (cross-host polling + SSRF amplification). The cross-host URL
// must be skipped, so a thumbprint the cross-host list "revokes" keeps verifying.
func TestWellKnownAwareResolver_SkipsCrossHostRevocationURL(t *testing.T) {
	now := time.Now().UTC()
	priv, key := testutil.NewSigningKey(brokerRelaySeed, now.Add(-time.Hour), now.Add(1000*time.Hour))
	tp := testutil.MustThumbprintKey(t, key)

	// The revocation authority lives on a DIFFERENT host (a second origin, so a
	// different port ⇒ a different Host) than the directory.
	revOrigin := testutil.NewOrigin(nil)
	t.Cleanup(revOrigin.Close)
	revOrigin.SetRevocation(testutil.MarshalRevocation(time.Unix(2000, 0), tp))

	origin := testutil.NewOrigin(nil)
	t.Cleanup(origin.Close)
	f := testutil.WBAFile(key)
	f.RevocationUrl = testutil.Ptr(revOrigin.RevocationURL()) // cross-host
	origin.SetWBA(testutil.MarshalWBA(f))

	srv := startRevocationResolverServer(t, origin.URL)

	// The cross-host revocation_url is not anchored to the directory host, so the
	// poller never fetches it: the thumbprint the cross-host list "revokes" keeps
	// verifying across every poll cycle. Were the host-anchor gate dropped, the
	// poller would fetch revOrigin and the key would flip to 401.
	if status := signedDiscoverStatus(t, srv, tp, priv); status != http.StatusOK {
		t.Fatalf("cross-host revocation: status = %d, want 200", status)
	}
	requireStableStatus(t, srv, tp, priv, http.StatusOK, time.Second)
}

// TestWellKnownAwareResolver_ClampsFutureAsOfSkew pins control (3), the 300s
// as_of future-skew clamp. A compromised or misconfigured origin could otherwise
// stamp a far-future as_of that becomes an unreachable baseline, freezing every
// subsequent (legitimately earlier) snapshot under the monotonic guard. The clamp
// pins each snapshot's effective as_of to now+300s, so a later revoking snapshot
// still applies even when both carry the same far-future raw as_of.
func TestWellKnownAwareResolver_ClampsFutureAsOfSkew(t *testing.T) {
	now := time.Now().UTC()
	priv, key := testutil.NewSigningKey(brokerRelaySeed, now.Add(-time.Hour), now.Add(1000*time.Hour))
	tp := testutil.MustThumbprintKey(t, key)
	farFuture := now.Add(365 * 24 * time.Hour) // way past the 300s skew ceiling

	origin := testutil.NewOrigin(nil)
	t.Cleanup(origin.Close)
	f := testutil.WBAFile(key)
	f.RevocationUrl = testutil.Ptr(origin.RevocationURL())
	origin.SetWBA(testutil.MarshalWBA(f))
	// First snapshot: empty, stamped far in the future.
	origin.SetRevocation(testutil.MarshalRevocation(farFuture))

	srv := startRevocationResolverServer(t, origin.URL)

	if status := signedDiscoverStatus(t, srv, tp, priv); status != http.StatusOK {
		t.Fatalf("pre-revocation: status = %d, want 200", status)
	}

	// A later snapshot — same far-future raw as_of — revokes the key. Because the
	// clamp pins each snapshot's effective as_of to now+300s, the later poll's
	// snapshot is strictly newer and IS applied. Without the clamp the equal
	// far-future as_of would read as a rollback and this revocation would never
	// take effect (the key would stay 200 and this test would fail).
	origin.SetRevocation(testutil.MarshalRevocation(farFuture, tp))
	pollForStatus(t, srv, tp, priv, http.StatusUnauthorized, 5*time.Second)
}

// TestWellKnownAwareResolver_IgnoresRolledBackAsOf pins control (4), the
// monotonic rollback guard. After a newer as_of snapshot revokes a key, a fetched
// snapshot whose as_of is not strictly newer (a stale cache, a replayed prior
// snapshot, a regressed document) must be ignored — a revoked key must never be
// silently un-revoked.
func TestWellKnownAwareResolver_IgnoresRolledBackAsOf(t *testing.T) {
	now := time.Now().UTC()
	priv, key := testutil.NewSigningKey(brokerRelaySeed, now.Add(-time.Hour), now.Add(1000*time.Hour))
	tp := testutil.MustThumbprintKey(t, key)

	origin := testutil.NewOrigin(nil)
	t.Cleanup(origin.Close)
	f := testutil.WBAFile(key)
	f.RevocationUrl = testutil.Ptr(origin.RevocationURL())
	origin.SetWBA(testutil.MarshalWBA(f))
	// Newer snapshot revokes the key.
	origin.SetRevocation(testutil.MarshalRevocation(time.Unix(2000, 0), tp))

	srv := startRevocationResolverServer(t, origin.URL)

	pollForStatus(t, srv, tp, priv, http.StatusUnauthorized, 5*time.Second)

	// Roll back to an OLDER as_of that no longer lists the key. The monotonic
	// guard ignores it, so the key stays rejected across every subsequent poll
	// cycle. Were the guard dropped, the older empty snapshot would un-revoke the
	// key and it would flip back to 200.
	origin.SetRevocation(testutil.MarshalRevocation(time.Unix(1000, 0)))
	requireStableStatus(t, srv, tp, priv, http.StatusUnauthorized, time.Second)
}

// startRevocationResolverServer wires the production wellKnownAwareResolver
// (broker revocation channel ahead of an empty fall-through delegate) against
// brokerURL and mounts it behind the RFC 9421 verify handler — the same
// composition buildHTTPSigDeps exports. The loopback origin uses http.DefaultClient
// (not the guarded client the production default would install) because the
// SSRF guard would correctly refuse a loopback target.
func startRevocationResolverServer(t *testing.T, brokerURL string) *httptest.Server {
	t.Helper()
	t.Setenv("EXCHANGE_REVOCATION_POLL_INTERVAL", "150ms")
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	resolver := wellKnownAwareResolver(ctx, brokerURL, helpers.NewStaticKeyResolver(nil), http.DefaultClient, slog.Default())
	return newHTTPSigServer(t, resolver)
}

// pollForStatus signs a fresh DiscoverResources call as (tp, priv) until the
// verify handler returns want or the deadline passes (fatal). It waits for a
// revocation poller cycle to take effect.
func pollForStatus(
	t *testing.T, srv *httptest.Server, tp string, priv ed25519.PrivateKey, want int, within time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(within)
	for {
		if signedDiscoverStatus(t, srv, tp, priv) == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("status never reached %d within %s", want, within)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// requireStableStatus asserts every signed call over window returns want. It
// proves a control PREVENTS a status change (host-anchor skip, monotonic
// rollback ignore) that would otherwise land once a poller cycle ran.
func requireStableStatus(
	t *testing.T, srv *httptest.Server, tp string, priv ed25519.PrivateKey, want int, window time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(window)
	for time.Now().Before(deadline) {
		if got := signedDiscoverStatus(t, srv, tp, priv); got != want {
			t.Fatalf("status = %d, want stable %d", got, want)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// newHTTPSigServer mounts resolver behind an inline RFC 9421 verify handler
// (using helpers.VerifyRequestResolved) over a 200-OK handler and returns the
// test server. This replaces the deleted httpsig.Middleware, exercising the
// same resolver contract without the removed internal package.
func newHTTPSigServer(t *testing.T, resolver helpers.KeyResolver) *httptest.Server {
	t.Helper()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
			return
		}
		if _, err := helpers.VerifyRequestResolved(r.Context(), r, body, resolver, helpers.VerifyOptions{}); err != nil {
			http.Error(w, "httpsig: "+err.Error(), http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	return srv
}

// signedDiscoverStatus signs a fresh DiscoverResources call with keyid + priv
// and returns the HTTP status the verify handler assigns it.
func signedDiscoverStatus(t *testing.T, srv *httptest.Server, keyid string, priv ed25519.PrivateKey) int {
	t.Helper()
	const body = `{}`
	target := srv.URL + "/ramp.v1.ExchangeService/DiscoverResources"
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, bytes.NewReader([]byte(body)))
	if err != nil {
		t.Fatalf("new req: %v", err)
	}
	req.Host = req.URL.Host
	created := time.Now().Unix()
	signer, err := helpers.NewEd25519Signer(keyid, priv)
	if err != nil {
		t.Fatalf("new signer: %v", err)
	}
	opts := helpers.SignOptions{Created: created, Expires: created + 30}
	if err := helpers.SignRequest(req.Context(), req, []byte(body), signer, opts); err != nil {
		t.Fatalf("sign: %v", err)
	}
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	_ = resp.Body.Close()
	return resp.StatusCode
}

// TestBuildHTTPSigDeps_FailsClosedWithoutRevocationURL pins fail-closed boot:
// with EXCHANGE_BROKER_WELLKNOWN_URL unset, the Exchange MUST refuse to boot
// rather than proceed fail-open with only the per-agent well-known path (a key
// the Broker revoked would otherwise keep verifying). The success path (URL
// set) is covered by the other tests in this file that drive
// wellKnownAwareResolver.
func TestBuildHTTPSigDeps_FailsClosedWithoutRevocationURL(t *testing.T) {
	// EXCHANGE_BROKER_WELLKNOWN_URL is the revocation authority; unset it so the
	// fail-closed guard is what the composition hits. os.Unsetenv (not t.Setenv,
	// which cannot clear a variable) is safe here because this test does not run
	// in parallel and the variable is unset in the default test environment.
	if err := os.Unsetenv("EXCHANGE_BROKER_WELLKNOWN_URL"); err != nil {
		t.Fatalf("unset well-known url: %v", err)
	}

	// The guard must refuse BEFORE the per-agent resolver starts its poller
	// goroutine: goleak snapshots the goroutines alive at this instant and
	// fails the test if the refused boot left a new one behind. Swapping the
	// guard back below the poller start turns exactly that leak — the cancel
	// in Cleanup runs only after the check, so it cannot hide the regression,
	// while still reaping the goroutine afterwards so a failing run does not
	// poison later tests.
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	_, _, err := buildHTTPSigDeps(ctx, slog.Default(), http.DefaultClient)
	if err == nil {
		t.Fatal("buildHTTPSigDeps: expected a non-nil error when EXCHANGE_BROKER_WELLKNOWN_URL is unset, got nil (fail-open boot)")
	}
	if !strings.Contains(err.Error(), "EXCHANGE_BROKER_WELLKNOWN_URL") {
		t.Fatalf("buildHTTPSigDeps error = %q, want it to name EXCHANGE_BROKER_WELLKNOWN_URL", err)
	}
}
