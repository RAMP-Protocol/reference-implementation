package httpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// fixedKey returns a deterministic Ed25519 key from a one-byte seed pattern so
// the keys (not the wire bytes — yaronf stamps created=now() so signatures are
// no longer reproducible across runs) are stable across the chain tests.
func fixedKey(b byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return ed25519.NewKeyFromSeed(seed)
}

// signNow returns a near-now, second-truncated UTC instant for signing. The
// yaronf signer stamps created = time.Now().Unix() (its fake-created hook is
// unexported), so tests sign at real now and verify under a deterministic clock
// anchored at the same instant. Truncating to whole seconds keeps the verifier's
// created/expires comparisons exact.
func signNow() time.Time {
	return time.Now().UTC().Truncate(time.Second)
}

// TestChain_GoldenSignatureBehavior is the behavioral successor to the old
// byte-pinned TestChain_GoldenSignatureBase. yaronf/httpsign is now the
// canonicalization authority, so pinning the exact base string (and the old
// keyid;alg;created;expires param order) is no longer correct — the new param
// order is created;expires;alg;keyid. This test instead asserts the SECURITY
// property the golden test guarded (ADR-013 D5, Risk R1): a 2-sig
// forwarding chain verifies end-to-end, sig2 covers exactly one
// "signature";key="sig1" chain link, and the new wire param order is emitted.
func TestChain_GoldenSignatureBehavior(t *testing.T) {
	priv1 := fixedKey(0x01)
	priv2 := fixedKey(0x02)
	now := signNow()
	body := []byte(`{"query":"foo"}`)

	req := newRAMPSignedRequest(t, body, priv1, now)
	if err := AppendSignatureRAMP(req, body, "broker.relay.a", priv2, now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append: %v", err)
	}

	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		testKeyID:        priv1.Public().(ed25519.PublicKey),
		"broker.relay.a": priv2.Public().(ed25519.PublicKey),
	})
	verified, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if err != nil {
		t.Fatalf("verify chain: %v", err)
	}
	if len(verified) != 2 {
		t.Fatalf("got %d verified, want 2", len(verified))
	}

	allParams, _, err := parseAllSignatures(req.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	// sig1 carries no chain link; sig2 covers exactly one "signature";key="sig1".
	if _, count := chainLink(allParams[0].Covered); count != 0 {
		t.Fatalf("sig1 has %d chain links, want 0", count)
	}
	key, count := chainLink(allParams[1].Covered)
	if count != 1 || key != "sig1" {
		t.Fatalf("sig2 chain link = (%q, %d), want (sig1, 1)", key, count)
	}

	// Positive pin of the NEW canonical param order produced by yaronf:
	// created;expires;alg;keyid (not the old keyid;alg;created;expires).
	sigInput := req.Header.Get("Signature-Input")
	wantTail := `;alg="ed25519";keyid="broker.relay.a"`
	if !strings.Contains(sigInput, `created=`) || !strings.Contains(sigInput, wantTail) {
		t.Fatalf("Signature-Input param order/shape unexpected: %s", sigInput)
	}
	createdIdx := strings.Index(sigInput, "created=")
	algIdx := strings.Index(sigInput, `alg="ed25519"`)
	keyidIdx := strings.LastIndex(sigInput, "keyid=")
	if createdIdx >= algIdx || algIdx >= keyidIdx {
		t.Fatalf("param order is not created;...;alg;keyid: %s", sigInput)
	}
}

// TestChain_AppendAddsChainLink asserts AppendSignatureRAMP makes sig2 cover the
// base set plus exactly one "signature";key="sig1" link, and that sig1 carries no
// such link.
func TestChain_AppendAddsChainLink(t *testing.T) {
	priv1 := fixedKey(0x03)
	priv2 := fixedKey(0x04)
	now := signNow()
	body := []byte(`{"q":"x"}`)
	req := newRAMPSignedRequest(t, body, priv1, now)
	if err := AppendSignatureRAMP(req, body, "broker.relay.a", priv2, now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append: %v", err)
	}
	allParams, _, err := parseAllSignatures(req.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, count := chainLink(allParams[0].Covered); count != 0 {
		t.Fatalf("sig1 has %d chain links, want 0", count)
	}
	key, count := chainLink(allParams[1].Covered)
	if count != 1 || key != "sig1" {
		t.Fatalf("sig2 chain link = (%q, %d), want (sig1, 1)", key, count)
	}
}

// chainTestEnv builds a valid agent+broker (sig1+sig2) request and the resolver
// for it, shared by the rejection-vector tests.
func chainTestEnv(t *testing.T, now time.Time) (*http.Request, KeyResolver) {
	t.Helper()
	pub1 := fixedKey(0x05).Public().(ed25519.PublicKey)
	priv1 := fixedKey(0x05)
	pub2 := fixedKey(0x06).Public().(ed25519.PublicKey)
	priv2 := fixedKey(0x06)
	body := []byte(`{"q":"chain"}`)
	req := newRAMPSignedRequest(t, body, priv1, now)
	if err := AppendSignatureRAMP(req, body, "broker.relay.a", priv2, now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append: %v", err)
	}
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		testKeyID:        pub1,
		"broker.relay.a": pub2,
	})
	return req, resolver
}

// TestChain_ValidChainVerifies is the positive control for the rejection tests.
func TestChain_ValidChainVerifies(t *testing.T) {
	now := signNow()
	req, resolver := chainTestEnv(t, now)
	verified, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if len(verified) != 2 {
		t.Fatalf("got %d verified, want 2", len(verified))
	}
}

// TestChain_StrippedMiddleHop drops sig2 from a 3-sig chain, leaving sig1+sig3.
// The labels are no longer contiguous → ErrBrokenSignatureChain.
func TestChain_StrippedMiddleHop(t *testing.T) {
	now := signNow()
	priv1 := fixedKey(0x07)
	priv2 := fixedKey(0x08)
	priv3 := fixedKey(0x09)
	body := []byte(`{"q":"three"}`)
	req := newRAMPSignedRequest(t, body, priv1, now)
	if err := AppendSignatureRAMP(req, body, "broker.relay.a", priv2, now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append sig2: %v", err)
	}
	if err := AppendSignatureRAMP(req, body, "broker.relay.b", priv3, now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append sig3: %v", err)
	}
	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		testKeyID:        priv1.Public().(ed25519.PublicKey),
		"broker.relay.a": priv2.Public().(ed25519.PublicKey),
		"broker.relay.b": priv3.Public().(ed25519.PublicKey),
	})

	// Drop sig2 from both headers, leaving sig1, sig3.
	req.Header.Set("Signature-Input", dropLabel(req.Header.Get("Signature-Input"), "sig2"))
	req.Header.Set("Signature", dropLabel(req.Header.Get("Signature"), "sig2"))

	_, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrBrokenSignatureChain) {
		t.Fatalf("want ErrBrokenSignatureChain, got %v", err)
	}
	// Pin the SPECIFIC reason: after dropping sig2, sig3 sits at position 2 where
	// the chain expects sig2 — a contiguity failure, not some other structural one.
	if !strings.Contains(err.Error(), `want "sig2"`) {
		t.Fatalf("stripped-hop error should report the contiguity gap, got %v", err)
	}
}

// dropLabel removes the "label=..." member from a comma-separated structured
// field value (Signature / Signature-Input).
func dropLabel(raw, label string) string {
	var members []string
	for m := range strings.SplitSeq(raw, ", ") {
		if strings.HasPrefix(strings.TrimSpace(m), label+"=") {
			continue
		}
		members = append(members, m)
	}
	return strings.Join(members, ", ")
}

// TestChain_Reordered swaps sig1/sig2 header order → labels not contiguous in
// header order → ErrBrokenSignatureChain.
func TestChain_Reordered(t *testing.T) {
	now := signNow()
	req, resolver := chainTestEnv(t, now)

	req.Header.Set("Signature-Input", swapTwo(req.Header.Get("Signature-Input")))
	req.Header.Set("Signature", swapTwo(req.Header.Get("Signature")))

	_, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrBrokenSignatureChain) {
		t.Fatalf("want ErrBrokenSignatureChain, got %v", err)
	}
	// Pin the SPECIFIC reason: sig2 now sits at position 1 where sig1 is expected.
	if !strings.Contains(err.Error(), `want "sig1"`) {
		t.Fatalf("reorder error should report the position-1 mismatch, got %v", err)
	}
}

// swapTwo reverses a two-member comma-separated structured field value.
func swapTwo(raw string) string {
	parts := strings.SplitN(raw, ", ", 2)
	if len(parts) != 2 {
		return raw
	}
	return parts[1] + ", " + parts[0]
}

// TestChain_MissingLink builds a sig2 that does NOT cover sig1 (parallel-style)
// → ErrBrokenSignatureChain.
func TestChain_MissingLink(t *testing.T) {
	now := signNow()
	priv1 := fixedKey(0x0a)
	priv2 := fixedKey(0x0b)
	body := []byte(`{"q":"nolink"}`)
	req := newRAMPSignedRequest(t, body, priv1, now)

	// Append a sig2 with the PLAIN base set (no chain link) — the earlier
	// parallel co-sign shape that AppendSignatureRAMP can no longer emit. Driving
	// the production signWithParams primitive (not a hand-rolled base+sign+append)
	// keeps the wire-format emission in one place.
	params := Params{
		Label:   "sig2",
		Covered: rampCoveredComponents(req.Header),
		KeyID:   "broker.relay.a",
		Alg:     "ed25519",
		Created: now.Unix(),
		Expires: now.Add(30 * time.Second).Unix(),
	}
	if err := signWithParams(req, params, priv2, sigWriteAppend); err != nil {
		t.Fatalf("sign sig2: %v", err)
	}

	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		testKeyID:        priv1.Public().(ed25519.PublicKey),
		"broker.relay.a": priv2.Public().(ed25519.PublicKey),
	})
	_, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrBrokenSignatureChain) {
		t.Fatalf("want ErrBrokenSignatureChain, got %v", err)
	}
	if !strings.Contains(err.Error(), "must cover") {
		t.Fatalf("missing-link error should name the coverage failure, got %v", err)
	}
}

// TestChain_SubstitutedPredecessorRejected is the BINDING test (the property the
// forwarding chain exists for): a relay cannot swap a peer's signature. It takes
// a valid agent sig1_A + broker sig2 (which chained to sig1_A), then splices in a
// DIFFERENT but individually-valid agent sig1_B (same key + body + digest +
// method + target + authorization, but a different expires → different
// @signature-params → different signature bytes). sig1_B verifies on its own, but
// sig2's base resolves the chain link to sig1_B's bytes — which sig2 never
// signed — so sig2's Ed25519 verify fails. The other rejection tests stop at the
// structural enforceSignatureChain stage; this one exercises the cryptographic
// binding of the "signature";key="sig1" chain link.
//
// sig1_B differs from sig1_A only by its expires param (not by created, which
// yaronf stamps = now() and would collide within the same wall-clock second).
// Both expires values sit comfortably in the future of the verifier clock so the
// substituted sig1_B passes its own time-window check and the failure is
// unambiguously sig2's chain-link mismatch.
func TestChain_SubstitutedPredecessorRejected(t *testing.T) {
	now := signNow()
	agentPriv := fixedKey(0x0c)
	brokerPriv := fixedKey(0x0d)
	body := []byte(`{"q":"subst"}`)

	// Valid chain: agent sig1_A (expires now+30) + broker sig2 chaining to sig1_A.
	req := newRAMPSignedRequest(t, body, agentPriv, now)
	if err := AppendSignatureRAMP(req, nil, "broker.relay.a", brokerPriv, now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append sig2: %v", err)
	}

	// sig1_B: same agent key + body, but expires now+60 → different
	// @signature-params → different signature bytes. The agent could legitimately
	// produce this, but sig2 did not commit to it.
	reqB := newRAMPSignedRequestExpiring(t, body, agentPriv, now.Add(60*time.Second).Unix())
	sig1BInput := memberFor(reqB.Header.Get("Signature-Input"), "sig1")
	sig1BSig := memberFor(reqB.Header.Get("Signature"), "sig1")

	// Splice sig1_B over sig1_A, leaving the broker's sig2 untouched.
	req.Header.Set("Signature-Input", replaceLabelMember(req.Header.Get("Signature-Input"), "sig1", sig1BInput))
	req.Header.Set("Signature", replaceLabelMember(req.Header.Get("Signature"), "sig1", sig1BSig))

	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		testKeyID:        agentPriv.Public().(ed25519.PublicKey),
		"broker.relay.a": brokerPriv.Public().(ed25519.PublicKey),
	})
	_, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("want ErrSignatureVerify (sig2 bound to the substituted sig1), got %v", err)
	}
}

// newRAMPSignedRequestExpiring is the canonical RAMP-signed-request builder: it
// takes an explicit expires param so a second signature over the same message can
// differ in its @signature-params (and therefore its bytes) without relying on the
// wall-clock created stamp, which yaronf controls and truncates to whole seconds.
// newRAMPSignedRequest (verifier_test.go) delegates here with the standard now+30s.
func newRAMPSignedRequestExpiring(t *testing.T, body []byte, priv ed25519.PrivateKey, expires int64) *http.Request {
	t.Helper()
	return newRAMPSignedRequestMutated(t, body, priv, expires, nil)
}

// newRAMPSignedRequestMutated is the single definition of "a RAMP-signed
// request", with a hook that runs BEFORE signing. A test that cares how a
// particular header's WIRE BYTES are covered — and what a reader makes of them
// afterwards — has to set that header before the signature base is built, or it
// is asserting about a value the signature never committed to.
func newRAMPSignedRequestMutated(
	t *testing.T, body []byte, priv ed25519.PrivateKey, expires int64, mutate func(*http.Request),
) *http.Request {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		"https://exchange.example/ramp.v1.ExchangeService/DiscoverResources", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Host = "exchange.example"
	req.Header.Set("Authorization", "Bearer test-jwt")
	if mutate != nil {
		mutate(req)
	}
	if err := SignRequestRAMP(req, body, testKeyID, priv, expires); err != nil {
		t.Fatalf("sign: %v", err)
	}
	return req
}

// memberFor returns the "label=..." member for label from a comma-separated
// structured field value, trimmed.
func memberFor(raw, label string) string {
	for p := range strings.SplitSeq(raw, ", ") {
		if strings.HasPrefix(strings.TrimSpace(p), label+"=") {
			return strings.TrimSpace(p)
		}
	}
	return ""
}

// replaceLabelMember swaps the "label=..." member of a comma-separated structured
// field value for newMember, preserving order.
func replaceLabelMember(raw, label, newMember string) string {
	var parts []string
	for p := range strings.SplitSeq(raw, ", ") {
		if strings.HasPrefix(strings.TrimSpace(p), label+"=") {
			parts = append(parts, newMember)
		} else {
			parts = append(parts, p)
		}
	}
	return strings.Join(parts, ", ")
}

// TestChain_TooManyHops rejects a chain longer than MaxSignatures.
func TestChain_TooManyHops(t *testing.T) {
	now := signNow()
	req, resolver := chainTestEnv(t, now) // 2 signatures

	_, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{
		Clk:           clock.NewDeterministic(now),
		MaxSignatures: 1,
	})
	if !errors.Is(err, ErrTooManyHops) {
		t.Fatalf("want ErrTooManyHops, got %v", err)
	}
}

// TestChain_HopBudgetRejectedThroughMiddleware exercises the full hop-bound
// wiring: InterceptorOptions.MaxSignatures → verifyOpts → VerifyMultisigRequest,
// and the default reject responder (ErrTooManyHops → HTTP 429). The mapping from
// that sentinel to a Connect code is tested by
// internal/httpsig/transportconnect. MaxSignatures:2 mirrors the Exchange wiring
// (max_intermediary_hops + 1); a 3-signature chain must be rejected BEFORE crypto
// (so the test-server URL mismatch is irrelevant — the bound fires first).
func TestChain_HopBudgetRejectedThroughMiddleware(t *testing.T) {
	now := signNow()
	priv1 := fixedKey(0x0e)
	priv2 := fixedKey(0x0f)
	priv3 := fixedKey(0x10)
	body := []byte(`{"q":"budget"}`)

	signed := newRAMPSignedRequest(t, body, priv1, now)
	if err := AppendSignatureRAMP(signed, nil, "broker.relay.a", priv2, now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append sig2: %v", err)
	}
	if err := AppendSignatureRAMP(signed, nil, "broker.relay.b", priv3, now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append sig3: %v", err)
	}

	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		testKeyID:        priv1.Public().(ed25519.PublicKey),
		"broker.relay.a": priv2.Public().(ed25519.PublicKey),
		"broker.relay.b": priv3.Public().(ed25519.PublicKey),
	})

	var captured error
	gated := Middleware(resolver, NewMemoryReplayStore(nil), InterceptorOptions{
		RequestPredicate: func(*http.Request) bool { return true },
		MaxSignatures:    2,
		Clk:              clock.NewDeterministic(now),
		OnError:          func(_ *http.Request, err error) { captured = err },
	}, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	srv := httptest.NewServer(gated)
	defer srv.Close()

	out, err := http.NewRequestWithContext(context.Background(), http.MethodPost,
		srv.URL+"/ramp.v1.ExchangeService/ExecuteTransaction", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	for _, h := range []string{"Signature", "Signature-Input", "Content-Digest", "Authorization", "Content-Type"} {
		if v := signed.Header.Get(h); v != "" {
			out.Header.Set(h, v)
		}
	}
	resp, err := srv.Client().Do(out)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status = %d, want 429 (hop budget)", resp.StatusCode)
	}
	respBody, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(respBody), "hop budget") {
		t.Fatalf("body = %s, want hop-budget error", respBody)
	}
	if !errors.Is(captured, ErrTooManyHops) {
		t.Fatalf("captured err = %v, want ErrTooManyHops", captured)
	}
}

// TestChain_WithinHopBudget accepts a chain at exactly the budget.
func TestChain_WithinHopBudget(t *testing.T) {
	now := signNow()
	req, resolver := chainTestEnv(t, now) // 2 signatures
	if _, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{
		Clk:           clock.NewDeterministic(now),
		MaxSignatures: 2,
	}); err != nil {
		t.Fatalf("verify at budget: %v", err)
	}
}
