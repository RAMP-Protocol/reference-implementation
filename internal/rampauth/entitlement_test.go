package rampauth_test

import (
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampauth"
)

func TestReadEntitlementBiscuitAbsent(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
	got, err := rampauth.ReadEntitlementBiscuit(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Fatalf("want nil, got %x", got)
	}
}

func TestReadEntitlementBiscuitRawURL(t *testing.T) {
	want := []byte("biscuit-body")
	encoded := base64.RawURLEncoding.EncodeToString(want)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
	req.Header.Set(rampauth.EntitlementHeader, encoded)
	got, err := rampauth.ReadEntitlementBiscuit(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("want %q got %q", want, got)
	}
}

func TestReadEntitlementBiscuitStdPadded(t *testing.T) {
	want := []byte{0x00, 0xff, 0x10}
	encoded := base64.URLEncoding.EncodeToString(want)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
	req.Header.Set(rampauth.EntitlementHeader, encoded)
	got, err := rampauth.ReadEntitlementBiscuit(req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("want %v got %v", want, got)
	}
}

func TestReadEntitlementBiscuitTooLarge(t *testing.T) {
	oversized := strings.Repeat("A", rampauth.MaxEntitlementHeaderBytes+1)
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
	req.Header.Set(rampauth.EntitlementHeader, oversized)
	_, err := rampauth.ReadEntitlementBiscuit(req)
	if !errors.Is(err, rampauth.ErrHeaderTooLarge) {
		t.Fatalf("want ErrHeaderTooLarge, got %v", err)
	}
}

func TestReadEntitlementBiscuitInvalidBase64(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), "POST", "/", nil)
	req.Header.Set(rampauth.EntitlementHeader, "!!not-base64!!")
	_, err := rampauth.ReadEntitlementBiscuit(req)
	if !errors.Is(err, rampauth.ErrInvalidBase64) {
		t.Fatalf("want ErrInvalidBase64, got %v", err)
	}
}

func TestResolveBiscuit_NoneReturnsNil(t *testing.T) {
	out, err := rampauth.ResolveBiscuit(nil, nil, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if out != nil {
		t.Fatalf("want nil, got %v", out)
	}
}

func TestResolveBiscuit_HeaderOnly(t *testing.T) {
	out, err := rampauth.ResolveBiscuit([]byte("header-bytes"), nil, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(out) != "header-bytes" {
		t.Fatalf("want %q got %q", "header-bytes", out)
	}
}

func TestResolveBiscuit_EnvelopeOnly(t *testing.T) {
	out, err := rampauth.ResolveBiscuit(nil, []byte("env-bytes"), nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(out) != "env-bytes" {
		t.Fatalf("want %q got %q", "env-bytes", out)
	}
}

func TestResolveBiscuit_SubMessageOnly(t *testing.T) {
	out, err := rampauth.ResolveBiscuit(nil, nil, []byte("sub-bytes"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(out) != "sub-bytes" {
		t.Fatalf("want %q got %q", "sub-bytes", out)
	}
}

func TestResolveBiscuit_HeaderAndEnvelopeConflict(t *testing.T) {
	_, err := rampauth.ResolveBiscuit([]byte("h"), []byte("e"), nil)
	if !errors.Is(err, rampauth.ErrConflictingCarriers) {
		t.Fatalf("want ErrConflictingCarriers, got %v", err)
	}
}

func TestResolveBiscuit_HeaderAndSubMessageConflict(t *testing.T) {
	_, err := rampauth.ResolveBiscuit([]byte("h"), nil, []byte("s"))
	if !errors.Is(err, rampauth.ErrConflictingCarriers) {
		t.Fatalf("want ErrConflictingCarriers, got %v", err)
	}
}

func TestResolveBiscuit_EnvelopeAndSubMessageConflict(t *testing.T) {
	_, err := rampauth.ResolveBiscuit(nil, []byte("e"), []byte("s"))
	if !errors.Is(err, rampauth.ErrConflictingCarriers) {
		t.Fatalf("want ErrConflictingCarriers, got %v", err)
	}
}

func TestResolveBiscuit_AllThreeConflict(t *testing.T) {
	_, err := rampauth.ResolveBiscuit([]byte("h"), []byte("e"), []byte("s"))
	if !errors.Is(err, rampauth.ErrConflictingCarriers) {
		t.Fatalf("want ErrConflictingCarriers, got %v", err)
	}
}

func TestResolveBiscuit_IdenticalBytesAcrossTiersStillConflict(t *testing.T) {
	// ADR-005 §"Intake rule at Exchange" pins strict three-tier intake:
	// more than one populated carrier returns ErrConflictingCarriers
	// REGARDLESS of whether the bytes are byte-identical. The ADR's
	// rationale: "tolerant fallback would hide integration bugs at
	// bridges." Bridges (Broker, MCP shim, future envelope-aware
	// relays) MUST clear the inbound tier when they move the biscuit
	// to the outbound tier; a sender that populates two tiers — even
	// with identical bytes — has a bug and the strict rule surfaces
	// it at the first hop.
	raw := []byte("same-bytes")
	_, err := rampauth.ResolveBiscuit(raw, raw, nil)
	if !errors.Is(err, rampauth.ErrConflictingCarriers) {
		t.Fatalf("want ErrConflictingCarriers for byte-identical duplicate "+
			"across header+envelope, got %v", err)
	}
}

func TestResolveBiscuit_DifferentBytesInTwoTiersConflict(t *testing.T) {
	// Two tiers carry DIFFERENT bytes — a sender bug AND a smuggling
	// surface (an attacker who can plant a second biscuit alongside a
	// legitimate one). ADR-005 strict intake rejects this case
	// (subsumed by the byte-equal case above; kept as a distinct test
	// so a regression that re-introduces byte-equal tolerance doesn't
	// silently weaken the different-bytes path too).
	_, err := rampauth.ResolveBiscuit([]byte("a"), []byte("b"), nil)
	if !errors.Is(err, rampauth.ErrConflictingCarriers) {
		t.Fatalf("want ErrConflictingCarriers, got %v", err)
	}
}

func TestResolveBiscuit_EmptyCarriersTreatedAsAbsent(t *testing.T) {
	// Protobuf default for unset `optional bytes` is a zero-length byte
	// slice in Go; ResolveBiscuit MUST NOT raise a conflict when a
	// carrier is empty-not-nil.
	header := []byte("from-header")
	out, err := rampauth.ResolveBiscuit(header, []byte{}, []byte{})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(out) != "from-header" {
		t.Fatalf("want %q got %q", "from-header", out)
	}
}

func TestCanonicalBiscuit_ReadsHeaderFromCtx(t *testing.T) {
	ctx := rampauth.WithEntitlementBiscuit(context.Background(), []byte("header-bytes"))
	out, err := rampauth.CanonicalBiscuit(ctx, nil, nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(out) != "header-bytes" {
		t.Fatalf("want %q got %q", "header-bytes", out)
	}
}

func TestCanonicalBiscuit_SubMessageOnly(t *testing.T) {
	out, err := rampauth.CanonicalBiscuit(context.Background(), nil, []byte("sub-bytes"))
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(out) != "sub-bytes" {
		t.Fatalf("want %q got %q", "sub-bytes", out)
	}
}

func TestCanonicalBiscuit_EnvelopeOnlyFallback(t *testing.T) {
	out, err := rampauth.CanonicalBiscuit(context.Background(), []byte("env-bytes"), nil)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(out) != "env-bytes" {
		t.Fatalf("want %q got %q", "env-bytes", out)
	}
}

func TestCanonicalBiscuit_ConflictFromCtxAndEnvelope(t *testing.T) {
	ctx := rampauth.WithEntitlementBiscuit(context.Background(), []byte("h"))
	_, err := rampauth.CanonicalBiscuit(ctx, []byte("e"), nil)
	if !errors.Is(err, rampauth.ErrConflictingCarriers) {
		t.Fatalf("want ErrConflictingCarriers, got %v", err)
	}
}

func TestCanonicalBiscuit_ConflictFromCtxAndSubMessage(t *testing.T) {
	ctx := rampauth.WithEntitlementBiscuit(context.Background(), []byte("h"))
	_, err := rampauth.CanonicalBiscuit(ctx, nil, []byte("s"))
	if !errors.Is(err, rampauth.ErrConflictingCarriers) {
		t.Fatalf("want ErrConflictingCarriers, got %v", err)
	}
}

func TestEntitlementContextRoundTrip(t *testing.T) {
	raw := []byte("bits")
	ctx := rampauth.WithEntitlementBiscuit(context.Background(), raw)
	if got := rampauth.EntitlementBiscuitFromContext(ctx); string(got) != string(raw) {
		t.Fatalf("want %q got %q", raw, got)
	}
	if got := rampauth.EntitlementBiscuitFromContext(context.Background()); got != nil {
		t.Fatalf("want nil from empty context, got %x", got)
	}
}
