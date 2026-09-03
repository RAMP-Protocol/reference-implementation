package publisher_test

// The RAMP commercial overlay's own tests: what decides that it is served, and what
// happens when the account store cannot answer. The document itself is derived from
// the subdomain, so these are all presence and availability questions.

import (
	"context"
	"errors"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/publisher"
)

// stubRegistrations answers whether a subdomain names a registered agent. Only the
// error matters to the publisher — the overlay is derived from the subdomain, not from
// any field of the account row — so the success case returns the zero Developer.
type stubRegistrations struct {
	err   error
	calls int
}

func (s *stubRegistrations) BySubdomain(_ context.Context, _ string) (account.Developer, error) {
	s.calls++
	return account.Developer{}, s.err
}

// registered is the stub for a subdomain that has an account row.
func registered() *stubRegistrations { return &stubRegistrations{} }

// TestManifestPresenceFollowsTheAccountRow pins what decides whether the overlay is
// served. The account row is the only input: an agent with a row gets one even when it
// publishes nothing else, and an agent with keys and a card gets none without a row.
// The second case is the one a cheaper rule would get wrong — deriving presence from
// the sibling documents would publish a role marker for a domain nobody registered.
func TestManifestPresenceFollowsTheAccountRow(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name       string
		keys       *stubKeys
		cards      *stubCards
		regs       *stubRegistrations
		wantServed bool
	}{
		{
			name: "account row only", keys: &stubKeys{},
			cards: &stubCards{err: directory.ErrCardNotFound},
			regs:  registered(), wantServed: true,
		},
		{
			name: "keys and card but no account row", keys: &stubKeys{keys: []keystore.Key{aKey(t)}},
			cards: &stubCards{card: directory.Card{ClientName: "x", ClientURI: "https://x"}},
			regs:  &stubRegistrations{err: account.ErrNotFound}, wantServed: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			svc := newSvc(t, publisher.Config{Keys: tc.keys, Cards: tc.cards, Registrations: tc.regs})
			body, err := svc.Manifest(context.Background(), validSub)
			if !tc.wantServed {
				if !errors.Is(err, publisher.ErrAbsent) {
					t.Fatalf("Manifest err = %v, want ErrAbsent", err)
				}
				return
			}
			if err != nil || len(body) == 0 {
				t.Fatalf("Manifest = (%d bytes, %v), want non-empty, nil", len(body), err)
			}
			m, parseErr := rampwellknown.ParseManifest(body, rampwellknown.RoleAgent)
			if parseErr != nil {
				t.Fatalf("built manifest invalid: %v", parseErr)
			}
			if m.GetDomain() != validSub {
				t.Errorf("manifest domain = %q, want %q", m.GetDomain(), validSub)
			}
		})
	}
}

// TestManifestUnavailableWhenAccountStoreIsDown separates "this agent is not
// registered" from "we could not find out". Answering 404 during an outage would tell a
// consumer the agent does not exist, which is a different and durable-sounding claim.
func TestManifestUnavailableWhenAccountStoreIsDown(t *testing.T) {
	t.Parallel()
	svc := newSvc(t, publisher.Config{
		Keys:          &stubKeys{keys: []keystore.Key{aKey(t)}},
		Cards:         &stubCards{err: directory.ErrCardNotFound},
		Registrations: &stubRegistrations{err: account.ErrUnavailable},
	})
	if _, err := svc.Manifest(context.Background(), validSub); !errors.Is(err, publisher.ErrUnavailable) {
		t.Fatalf("Manifest err = %v, want ErrUnavailable", err)
	}
	// The outage is confined to the overlay: the directory has its own backend and
	// must keep answering.
	if body, err := svc.Directory(context.Background(), validSub); err != nil || len(body) == 0 {
		t.Fatalf("Directory = (%d bytes, %v), want non-empty, nil during an account-store outage", len(body), err)
	}
}

// TestManifestOnlyAgentIsNotNegativeCached covers the account-row-only agent across two
// calls. The publisher remembers a subdomain that is absent from every source so a
// flood of unknown hosts costs one backend round-trip each; an agent whose only
// published document is the overlay must not be filed there, or its second request
// would 404 for the whole negative TTL. The stub's call count also shows the second
// answer came from the positive cache rather than a rebuild.
func TestManifestOnlyAgentIsNotNegativeCached(t *testing.T) {
	t.Parallel()
	regs := registered()
	svc := newSvc(t, publisher.Config{
		Keys:          &stubKeys{},
		Cards:         &stubCards{err: directory.ErrCardNotFound},
		Registrations: regs,
	})
	for i := 1; i <= 2; i++ {
		if body, err := svc.Manifest(context.Background(), validSub); err != nil || len(body) == 0 {
			t.Fatalf("call %d: Manifest = (%d bytes, %v), want non-empty, nil", i, len(body), err)
		}
	}
	if regs.calls != 1 {
		t.Errorf("account lookups = %d, want 1 (the second call should be served from cache)", regs.calls)
	}
}
