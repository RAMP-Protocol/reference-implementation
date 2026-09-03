package signup_test

import (
	"context"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oidcup"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/signup"
)

// --- fakes for the signup ports (pure, in-memory) ---

type fakeStore struct {
	subjects   map[string]account.Developer
	subdomains map[string]bool
}

func newFakeStore() *fakeStore {
	return &fakeStore{subjects: map[string]account.Developer{}, subdomains: map[string]bool{}}
}

func skey(iss, sub string) string { return iss + "\x00" + sub }

func (f *fakeStore) BySubject(_ context.Context, iss, sub string) (account.Developer, error) {
	if d, ok := f.subjects[skey(iss, sub)]; ok {
		return d, nil
	}
	return account.Developer{}, account.ErrNotFound
}

func (f *fakeStore) Reserve(_ context.Context, d account.Developer) (account.Developer, error) {
	if _, ok := f.subjects[skey(d.Issuer, d.Subject)]; ok {
		return account.Developer{}, account.ErrAlreadyExists
	}
	if f.subdomains[d.Subdomain] {
		return account.Developer{}, account.ErrSubdomainTaken
	}
	f.subdomains[d.Subdomain] = true
	f.subjects[skey(d.Issuer, d.Subject)] = d
	return d, nil
}

type fakeKeys struct {
	created  map[string]int
	existing map[string]bool
}

func newFakeKeys() *fakeKeys {
	return &fakeKeys{created: map[string]int{}, existing: map[string]bool{}}
}

func (f *fakeKeys) List(_ context.Context, subdomain string) ([]keystore.Key, error) {
	if f.existing[subdomain] {
		return []keystore.Key{{Ref: keystore.Ref{Subdomain: subdomain}}}, nil
	}
	return nil, nil
}

func (f *fakeKeys) Create(_ context.Context, subdomain string, _ keystore.Window) (keystore.Key, error) {
	f.created[subdomain]++
	f.existing[subdomain] = true
	return keystore.Key{Ref: keystore.Ref{Subdomain: subdomain}}, nil
}

type fakeCards struct{ upserts map[string]directory.Card }

func (f *fakeCards) Upsert(_ context.Context, subdomain string, card directory.Card) (directory.Card, error) {
	f.upserts[subdomain] = card
	return card, nil
}

type fakeInval struct{ calls []string }

func (f *fakeInval) Invalidate(s string) { f.calls = append(f.calls, s) }

type fakeSlugs struct {
	seq []string
	i   int
}

func (f *fakeSlugs) New() (string, error) {
	s := f.seq[f.i%len(f.seq)]
	f.i++
	return s, nil
}

type harness struct {
	svc   *signup.Service
	store *fakeStore
	keys  *fakeKeys
	cards *fakeCards
	inval *fakeInval
}

func newHarness(t *testing.T, slugs ...string) harness {
	t.Helper()
	h := harness{
		store: newFakeStore(),
		keys:  newFakeKeys(),
		cards: &fakeCards{upserts: map[string]directory.Card{}},
		inval: &fakeInval{},
	}
	svc, err := signup.New(signup.Config{
		Keys:        h.keys,
		Cards:       h.cards,
		Developers:  h.store,
		Slugs:       &fakeSlugs{seq: slugs},
		Invalidator: h.inval,
		Clock:       clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC)),
		BaseDomain:  "rampmcp.org",
	})
	if err != nil {
		t.Fatalf("signup.New: %v", err)
	}
	h.svc = svc
	return h
}

var claims = oidcup.Claims{
	Issuer:  "https://zitadel.example",
	Subject: "user-1",
	Email:   "dev@acme.example",
	Name:    "Dev One",
}

func TestSignIn_NewDeveloperProvisions(t *testing.T) {
	h := newHarness(t, "agent-aaaa1111")
	sub, err := h.svc.SignIn(context.Background(), claims)
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if sub != "agent-aaaa1111.rampmcp.org" {
		t.Errorf("subdomain = %q, want the minted FQDN", sub)
	}
	if h.keys.created[sub] != 1 {
		t.Errorf("key create count = %d, want exactly 1", h.keys.created[sub])
	}
	card, ok := h.cards.upserts[sub]
	if !ok || card.ClientURI != "https://"+sub || card.ClientName != "Dev One" {
		t.Errorf("card = %+v (present=%v), want claims-derived values", card, ok)
	}
	if len(h.inval.calls) != 1 || h.inval.calls[0] != sub {
		t.Errorf("invalidate calls = %v, want exactly [%s]", h.inval.calls, sub)
	}
}

func TestSignIn_ReturningDeveloperIsStable(t *testing.T) {
	h := newHarness(t, "agent-aaaa1111")
	first, err := h.svc.SignIn(context.Background(), claims)
	if err != nil {
		t.Fatalf("first SignIn: %v", err)
	}
	// Second sign-in of the same identity must reuse the subdomain and not mint a
	// second first-key.
	second, err := h.svc.SignIn(context.Background(), claims)
	if err != nil {
		t.Fatalf("second SignIn: %v", err)
	}
	if second != first {
		t.Errorf("subdomain changed across sign-ins: %q then %q", first, second)
	}
	if h.keys.created[first] != 1 {
		t.Errorf("key create count = %d after two sign-ins, want 1", h.keys.created[first])
	}
}

func TestSignIn_RetriesOnSlugCollision(t *testing.T) {
	h := newHarness(t, "agent-taken000", "agent-free0001")
	h.store.subdomains["agent-taken000.rampmcp.org"] = true // first slug is already claimed

	sub, err := h.svc.SignIn(context.Background(), claims)
	if err != nil {
		t.Fatalf("SignIn: %v", err)
	}
	if sub != "agent-free0001.rampmcp.org" {
		t.Errorf("subdomain = %q, want the second (free) slug", sub)
	}
}
