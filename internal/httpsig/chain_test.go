package httpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// fixedKey returns a deterministic Ed25519 key from a one-byte seed pattern so
// signature bases and bytes are reproducible across runs (golden vectors).
func fixedKey(b byte) ed25519.PrivateKey {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = b
	}
	return ed25519.NewKeyFromSeed(seed)
}

// TestChain_GoldenSignatureBase pins the byte-exact signature base for a 2-sig
// forwarding chain (the RAMP-56 / ADR-013 D5 contract). It guards Risk R1: the
// "signature";key="sig1" component must resolve to the canonical
// :base64(sig1bytes): value, byte-equal to sig1's own Signature header member.
func TestChain_GoldenSignatureBase(t *testing.T) {
	priv1 := fixedKey(0x01)
	priv2 := fixedKey(0x02)
	now := time.Unix(1700000000, 0)
	body := []byte(`{"query":"foo"}`)

	req := newRAMPSignedRequest(t, body, priv1, now)
	if err := AppendSignatureRAMP(req, body, "broker.relay.a", priv2, now.Unix(), now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append: %v", err)
	}

	digest := "sha-256=:" + base64.StdEncoding.EncodeToString(sha256Sum(body)) + ":"

	// sig1 base — exact format (line ordering, separators, @signature-params).
	wantSig1Base := strings.Join([]string{
		`"@method": POST`,
		`"@target-uri": https://exchange.example/ramp.v1.ExchangeService/DiscoverResources`,
		`"content-digest": ` + digest,
		`"authorization": Bearer test-jwt`,
		`"@signature-params": ("@method" "@target-uri" "content-digest" "authorization");keyid="agent-demo.v1";alg="ed25519";created=1700000000;expires=1700000030`,
	}, "\n")

	allParams, _, err := parseAllSignatures(req.Header)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	gotSig1Base, err := buildSignatureBase(req, allParams[0])
	if err != nil {
		t.Fatalf("build sig1 base: %v", err)
	}
	if gotSig1Base != wantSig1Base {
		t.Fatalf("sig1 base mismatch:\n got:\n%s\nwant:\n%s", gotSig1Base, wantSig1Base)
	}

	// sig2 base must carry the chain link whose value equals sig1's wire member.
	sig1Bytes, err := parseSignatureField(req.Header.Get("Signature"), "sig1")
	if err != nil {
		t.Fatalf("parse sig1 bytes: %v", err)
	}
	sig1Wire := ":" + base64.StdEncoding.EncodeToString(sig1Bytes) + ":"
	wantChainLine := `"signature";key="sig1": ` + sig1Wire

	gotSig2Base, err := buildSignatureBase(req, allParams[1])
	if err != nil {
		t.Fatalf("build sig2 base: %v", err)
	}
	if !strings.Contains(gotSig2Base, wantChainLine) {
		t.Fatalf("sig2 base missing chain line %q:\n%s", wantChainLine, gotSig2Base)
	}

	// Symmetry: the @signature-params inner list in the base equals the
	// Signature-Input header inner list for sig2 (no rendering drift).
	wantInner := `("@method" "@target-uri" "content-digest" "authorization" "signature";key="sig1")`
	if !strings.Contains(gotSig2Base, wantInner) {
		t.Fatalf("sig2 @signature-params inner list mismatch:\n%s", gotSig2Base)
	}
	if !strings.Contains(req.Header.Get("Signature-Input"), wantInner) {
		t.Fatalf("Signature-Input sig2 inner list mismatch:\n%s", req.Header.Get("Signature-Input"))
	}
}

func sha256Sum(b []byte) []byte {
	s := sha256.Sum256(b)
	return s[:]
}

// TestChain_AppendAddsChainLink asserts AppendSignatureRAMP makes sig2 cover the
// base set plus exactly one "signature";key="sig1" link, and that sig1 carries no
// such link.
func TestChain_AppendAddsChainLink(t *testing.T) {
	priv1 := fixedKey(0x03)
	priv2 := fixedKey(0x04)
	now := time.Unix(1700000000, 0)
	body := []byte(`{"q":"x"}`)
	req := newRAMPSignedRequest(t, body, priv1, now)
	if err := AppendSignatureRAMP(req, body, "broker.relay.a", priv2, now.Unix(), now.Add(30*time.Second).Unix()); err != nil {
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
	if err := AppendSignatureRAMP(req, body, "broker.relay.a", priv2, now.Unix(), now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append: %v", err)
	}
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
		testKeyID:        pub1,
		"broker.relay.a": pub2,
	})
	return req, resolver
}

// TestChain_ValidChainVerifies is the positive control for the rejection tests.
func TestChain_ValidChainVerifies(t *testing.T) {
	now := time.Unix(1700000000, 0)
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
	now := time.Unix(1700000000, 0)
	priv1 := fixedKey(0x07)
	priv2 := fixedKey(0x08)
	priv3 := fixedKey(0x09)
	body := []byte(`{"q":"three"}`)
	req := newRAMPSignedRequest(t, body, priv1, now)
	if err := AppendSignatureRAMP(req, body, "broker.relay.a", priv2, now.Unix(), now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append sig2: %v", err)
	}
	if err := AppendSignatureRAMP(req, body, "broker.relay.b", priv3, now.Unix(), now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append sig3: %v", err)
	}
	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
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
	now := time.Unix(1700000000, 0)
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
	now := time.Unix(1700000000, 0)
	priv1 := fixedKey(0x0a)
	priv2 := fixedKey(0x0b)
	body := []byte(`{"q":"nolink"}`)
	req := newRAMPSignedRequest(t, body, priv1, now)

	// Append a sig2 with the PLAIN base set (no chain link) — the pre-RAMP-56
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

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
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
// DIFFERENT but individually-valid agent sig1_B (same key + body, different
// created). sig1_B verifies on its own, but sig2's base resolves the chain link
// to sig1_B's bytes — which sig2 never signed — so sig2's Ed25519 verify fails.
// The other rejection tests stop at the structural enforceSignatureChain stage;
// this one exercises the cryptographic binding in chainLinkValue.
func TestChain_SubstitutedPredecessorRejected(t *testing.T) {
	now := time.Unix(1700000000, 0)
	agentPriv := fixedKey(0x0c)
	brokerPriv := fixedKey(0x0d)
	body := []byte(`{"q":"subst"}`)

	// Valid chain: agent sig1_A + broker sig2 chaining to sig1_A.
	req := newRAMPSignedRequest(t, body, agentPriv, now)
	if err := AppendSignatureRAMP(req, nil, "broker.relay.a", brokerPriv, now.Unix(), now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append sig2: %v", err)
	}

	// sig1_B: same agent key + body, different created → different signature bytes.
	// The agent could legitimately produce this, but sig2 did not commit to it.
	reqB := newRAMPSignedRequest(t, body, agentPriv, now.Add(time.Second))
	sig1BInput := memberFor(reqB.Header.Get("Signature-Input"), "sig1")
	sig1BSig := memberFor(reqB.Header.Get("Signature"), "sig1")

	// Splice sig1_B over sig1_A, leaving the broker's sig2 untouched.
	req.Header.Set("Signature-Input", replaceLabelMember(req.Header.Get("Signature-Input"), "sig1", sig1BInput))
	req.Header.Set("Signature", replaceLabelMember(req.Header.Get("Signature"), "sig1", sig1BSig))

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
		testKeyID:        agentPriv.Public().(ed25519.PublicKey),
		"broker.relay.a": brokerPriv.Public().(ed25519.PublicKey),
	})
	_, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: clock.NewDeterministic(now)})
	if !errors.Is(err, ErrSignatureVerify) {
		t.Fatalf("want ErrSignatureVerify (sig2 bound to the substituted sig1), got %v", err)
	}
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
	now := time.Unix(1700000000, 0)
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
// and the default reject responder (ErrTooManyHops → HTTP 429). The Connect-code
// and REJECTED_HOP_BUDGET audit-token mapping lives in — and is tested by —
// internal/httpsig/transportconnect. MaxSignatures:2 mirrors the Exchange wiring
// (max_intermediary_hops + 1); a 3-signature chain must be rejected BEFORE crypto
// (so the test-server URL mismatch is irrelevant — the bound fires first).
func TestChain_HopBudgetRejectedThroughMiddleware(t *testing.T) {
	now := time.Unix(1700000000, 0)
	priv1 := fixedKey(0x0e)
	priv2 := fixedKey(0x0f)
	priv3 := fixedKey(0x10)
	body := []byte(`{"q":"budget"}`)

	signed := newRAMPSignedRequest(t, body, priv1, now)
	if err := AppendSignatureRAMP(signed, nil, "broker.relay.a", priv2, now.Unix(), now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append sig2: %v", err)
	}
	if err := AppendSignatureRAMP(signed, nil, "broker.relay.b", priv3, now.Unix(), now.Add(30*time.Second).Unix()); err != nil {
		t.Fatalf("append sig3: %v", err)
	}

	resolver := NewStaticResolver(map[string]ed25519.PublicKey{
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
	now := time.Unix(1700000000, 0)
	req, resolver := chainTestEnv(t, now) // 2 signatures
	if _, err := VerifyMultisigRequest(req, resolver, VerifyRequestOptions{
		Clk:           clock.NewDeterministic(now),
		MaxSignatures: 2,
	}); err != nil {
		t.Fatalf("verify at budget: %v", err)
	}
}
