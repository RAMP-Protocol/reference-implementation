//go:build integration

package transport_test

// The relay's dependence on the SDK seeding the Signature-Agent directory.
//
// relay.verifyAgentSignature used to seed helpers.WithSignatureAgent onto the
// context itself before calling VerifyRequestResolved. That seeding was deleted
// as redundant — VerifyRequestResolved reads the header off the request and
// installs it before invoking the resolver, so a value seeded by the caller is
// overwritten on every path. Correct against the current pin, and invisible to
// every other relay test, because they all resolve the agent's key from a
// thumbprint-keyed static map that never looks at the directory.
//
// That is the gap this file closes. After the WBA split the RFC 9421 keyid is
// only a proof-of-possession thumbprint, so a never-seen agent's key can be found
// ONLY by fetching the directory its covered Signature-Agent header names. If an
// SDK bump moved that seeding, unregistered-agent relay verification would break
// and the rest of the suite would stay green.
//
// The resolver below is therefore directory-driven, the way the production
// resolver is: it ignores the keyid and answers from the context value alone. If
// the SDK stops installing it, the resolver is handed "" and the relay returns
// 401 instead of relaying.

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"io"
	"net/http"
	"sync"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// directoryKeyedResolver answers from the signed Signature-Agent directory rather
// than the keyid, and records what it was given so a failure names the value
// rather than only the status code.
type directoryKeyedResolver struct {
	mu        sync.Mutex
	byDirect  map[string]ed25519.PublicKey
	seen      []string
	callCount int
}

func (r *directoryKeyedResolver) Resolve(
	ctx context.Context, _ string,
) (ed25519.PublicKey, error) {
	directory := helpers.SignatureAgentFromContext(ctx)
	r.mu.Lock()
	r.callCount++
	r.seen = append(r.seen, directory)
	pub, ok := r.byDirect[directory]
	r.mu.Unlock()
	if !ok {
		return nil, fmt.Errorf("%w: no key published at directory %q",
			helpers.ErrUnknownKey, directory)
	}
	return pub, nil
}

func (r *directoryKeyedResolver) observed() (int, []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.callCount, append([]string(nil), r.seen...)
}

// TestDiscoverRelay_ResolvesAgentKeyFromSignedDirectory drives the relay with a
// resolver that can only succeed if the SDK put the signed Signature-Agent
// directory into the resolver's context.
//
// The header is sent in the QUOTED structured-field form Web Bot Auth defines,
// which is what a conformant signer emits, so this also pins that the unwrapping
// happens upstream of the resolver — a resolver handed a directory URI still
// carrying its quotes can parse no host out of it and would fail the request.
func TestDiscoverRelay_ResolvesAgentKeyFromSignedDirectory(t *testing.T) {
	const directory = "https://agent.test.example"

	resolver := &directoryKeyedResolver{byDirect: map[string]ed25519.PublicKey{}}
	env := newDiscoverRelayTestEnvResolvedBy(t,
		func(_ string, agentPub ed25519.PublicKey) helpers.KeyResolver {
			// Keyed on the directory ONLY. The agent's thumbprint keyid is not in
			// this map, so a resolver reached without the directory cannot succeed
			// by accident.
			resolver.byDirect[directory] = agentPub
			return resolver
		})
	env.signatureAgent = `"` + directory + `"`

	body := env.queryBody(t)
	resp, err := http.DefaultClient.Do(env.signedDiscoverRequest(t, body, true))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()
	bodyBytes, _ := io.ReadAll(resp.Body)

	calls, seen := resolver.observed()
	if calls == 0 {
		t.Fatal("the resolver was never reached; the assertions below would be vacuous")
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("relay refused a correctly signed request: %d %s\n"+
			"the resolver saw directories %q — if that is empty, the SDK no longer seeds "+
			"the signed Signature-Agent into the resolver context, and the relay must seed it again",
			resp.StatusCode, bodyBytes, seen)
	}
	for _, got := range seen {
		if got != directory {
			t.Errorf("resolver context directory = %q; want %q — the quoted wire form must be "+
				"unwrapped before the resolver, which cannot fetch a directory carrying quotes",
				got, directory)
		}
	}
	if env.mockExch.discoverCalls != 1 {
		t.Errorf("Exchange.DiscoverResources called %d times, want 1", env.mockExch.discoverCalls)
	}
}

// TestDiscoverRelay_UnknownDirectoryRefused is the negative half: the relay must
// refuse when the signed directory publishes no key for this signature, rather
// than falling back to some other lookup. Without it the test above could pass
// against a relay that admitted everything.
func TestDiscoverRelay_UnknownDirectoryRefused(t *testing.T) {
	resolver := &directoryKeyedResolver{byDirect: map[string]ed25519.PublicKey{}}
	env := newDiscoverRelayTestEnvResolvedBy(t,
		func(_ string, agentPub ed25519.PublicKey) helpers.KeyResolver {
			resolver.byDirect["https://agent.test.example"] = agentPub
			return resolver
		})
	// The agent signs a directory it has published no key at.
	env.signatureAgent = `"https://other.test.example"`

	body := env.queryBody(t)
	resp, err := http.DefaultClient.Do(env.signedDiscoverRequest(t, body, true))
	if err != nil {
		t.Fatalf("send to broker: %v", err)
	}
	defer resp.Body.Close()
	_, _ = io.ReadAll(resp.Body)

	// 401 specifically, not merely "not 200". A malformed-request 400 or a panic's
	// 500 would satisfy "not 200" while proving nothing about the key check, and
	// this test's whole subject is that the relay refused an AUTHENTICATION it
	// could not complete.
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 — a signature whose directory publishes no matching "+
			"key must be refused as unauthenticated, not fail some other way",
			resp.StatusCode)
	}
	if env.mockExch.discoverCalls != 0 {
		t.Errorf("Exchange.DiscoverResources called %d times, want 0 — a refused relay must not "+
			"reach the Exchange", env.mockExch.discoverCalls)
	}
	// The resolver MUST have been consulted. Skipping this check when it was not —
	// which the earlier form did, by guarding on len(seen) > 0 — excused exactly
	// the regression it exists to catch: a relay that refuses before ever looking
	// the key up passes every other assertion here.
	_, seen := resolver.observed()
	if len(seen) == 0 {
		t.Fatal("resolver was never consulted; the refusal came from somewhere other than " +
			"the key lookup, so this test proves nothing about it")
	}
	if seen[0] != "https://other.test.example" {
		t.Errorf("resolver context directory = %q; want the directory the agent actually signed", seen[0])
	}
}
