package main

// Wiring-level test: the offer Verifier built by newOfferVerifier makes its
// expiry decisions from the INJECTED clock, not an inline time.Now. The round
// trip is real: the verifier resolves the exchange's offer-signing key from a
// genuine WBA directory served over HTTP (the exchange is the external system —
// the adapter boundary), verifies a genuinely signed offer, and the verdict
// flips from verified to rejected purely by pinning the injected clock past the
// offer's expiry.

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

func TestNewOfferVerifier_ExpiryDrivenByInjectedClock(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/http-message-signatures-directory" {
			http.NotFound(w, r)
			return
		}
		doc := map[string]any{"keys": []map[string]string{{
			"kty": "OKP", "crv": "Ed25519", "use": "sig", "alg": "EdDSA",
			"x":          base64.RawURLEncoding.EncodeToString(pub),
			"not_before": "2000-01-01T00:00:00Z",
			"not_after":  "2100-01-01T00:00:00Z",
		}}}
		if err := json.NewEncoder(w).Encode(doc); err != nil {
			t.Errorf("encode wba doc: %v", err)
		}
	}))
	defer srv.Close()

	// The wiring builds its SDK-guarded fetch client + scheme from env; drop both
	// SDK guards (SKIP_SSRF for the loopback address, ALLOW_INSECURE for the http
	// scheme) and point the scheme at the local WBA server (the same knobs the e2e
	// stack uses).
	t.Setenv("SKIP_SSRF", "true")
	t.Setenv("ALLOW_INSECURE", "true")
	t.Setenv("RAMP_WELLKNOWN_SCHEME", "http")

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse server url: %v", err)
	}

	t0 := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	offer := &rampv1.Offer{
		OfferId:   "wiring-clock-offer",
		Exchange:  u.Host,
		ExpiresAt: timestamppb.New(t0.Add(time.Hour)),
	}
	sig, err := helpers.SignOffer(priv, offer)
	if err != nil {
		t.Fatalf("sign offer: %v", err)
	}
	offer.Signature = sig

	// Clock pinned BEFORE expiry: the genuinely signed offer verifies.
	freshVerifier := newOfferVerifier(clock.NewDeterministic(t0))
	fresh := freshVerifier.Sort(context.Background(), []*rampv1.Offer{offer})
	if len(fresh.Verified) != 1 || len(fresh.Rejected) != 0 {
		t.Fatalf("clock before expiry: verified=%d rejected=%d (want 1/0); rejected=%+v",
			len(fresh.Verified), len(fresh.Rejected), fresh.Rejected)
	}

	// Same offer, same key, clock pinned PAST expiry: rejected as expired. The
	// only variable is the injected clock — proving the expiry decision is
	// driven by it, not by the wall clock.
	staleVerifier := newOfferVerifier(clock.NewDeterministic(t0.Add(2 * time.Hour)))
	stale := staleVerifier.Sort(context.Background(), []*rampv1.Offer{offer})
	if len(stale.Verified) != 0 || len(stale.Rejected) != 1 {
		t.Fatalf("clock past expiry: verified=%d rejected=%d (want 0/1)",
			len(stale.Verified), len(stale.Rejected))
	}
	if !errors.Is(stale.Rejected[0].Reason, core.ErrOfferExpired) {
		t.Fatalf("rejection reason = %v; want core.ErrOfferExpired", stale.Rejected[0].Reason)
	}
}
