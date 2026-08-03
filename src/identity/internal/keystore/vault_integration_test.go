//go:build integration

package keystore_test

import (
	"crypto"
	"crypto/ed25519"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/pemkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	wkserver "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// This suite drives the custody layer through the KeyStore interface against a
// real Vault. Nothing here reads or writes a Vault path directly: the store is
// arranged and asserted through the same surface production uses, so a change
// that broke the storage layout while keeping the interface honest would still
// pass — and a change that broke the interface could not.

const agent = "agent-1.rampmcp.org"

// The whole point of custody: a key the service minted can sign, and what it
// signs verifies against the public half the service publishes.
func TestMintedKeySignsWhatItsPublishedPublicKeyVerifies(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	key, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	signer, err := store.Signer(ctx, key.Ref)
	if err != nil {
		t.Fatalf("signer: %v", err)
	}
	msg := []byte("GET /article HTTP/1.1")
	sig, err := signer.Sign(nil, msg, pureEd25519())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	// Verify against the public key read back through the interface, not the one
	// Create happened to return: this is the key a verifier would fetch.
	published, err := store.Active(ctx, agent)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if !ed25519.Verify(published.Public, msg, sig) {
		t.Error("signature does not verify against the agent's published key")
	}
	if published.Ref != key.Ref {
		t.Errorf("active key ref = %+v, want the one just minted %+v", published.Ref, key.Ref)
	}
}

// A rotation mints a second key while the first is still valid. Both must be
// published — that overlap is what keeps in-flight requests and cached copies of
// the directory verifying — but only the new one may sign.
func TestRotationOverlapPublishesBothKeysAndSignsWithTheNewest(t *testing.T) {
	store, clk := newStore(t)
	ctx := t.Context()

	old, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create old: %v", err)
	}
	clk.Advance(24 * time.Hour)
	fresh, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create fresh: %v", err)
	}

	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("published %d keys, want both keys of the overlap", len(keys))
	}
	if keys[0].Ref != fresh.Ref {
		t.Errorf("first published key is %q, want the newest %q — a consumer taking the "+
			"first key in document order would keep signing against the old one",
			keys[0].Ref.Thumbprint, fresh.Ref.Thumbprint)
	}
	if keys[1].Ref != old.Ref {
		t.Errorf("second published key = %q, want the older %q", keys[1].Ref.Thumbprint, old.Ref.Thumbprint)
	}

	active, err := store.Active(ctx, agent)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active.Ref != fresh.Ref {
		t.Errorf("signing key = %q, want the newly rotated key %q", active.Ref.Thumbprint, fresh.Ref.Thumbprint)
	}
}

// Two keys minted inside the same wall-clock second — a retried Create whose first
// attempt actually succeeded is the realistic way this happens — must still come back
// newest-first, and Active must still pick the newer. If storage rounds CreatedAt to
// the whole second the two stamps collide, the ordering falls through to a tie-break
// on thumbprint, and which key signs is then decided by a hash: right about half the
// time, and wrong the rest.
func TestKeysMintedInTheSameSecondStillOrderNewestFirst(t *testing.T) {
	store, clk := newStore(t)
	ctx := t.Context()

	older, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create the older key: %v", err)
	}
	clk.Advance(time.Millisecond) // same second, later instant
	newer, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create the newer key: %v", err)
	}

	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("list returned %d keys, want 2", len(keys))
	}
	if keys[0].Ref.Thumbprint != newer.Ref.Thumbprint {
		t.Errorf("list led with %q, want the newer key %q — two keys minted in the same "+
			"second must not be ordered by thumbprint",
			keys[0].Ref.Thumbprint, newer.Ref.Thumbprint)
	}

	active, err := store.Active(ctx, agent)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active.Ref.Thumbprint != newer.Ref.Thumbprint {
		t.Errorf("active = %q, want the newer key %q (the older is %q)",
			active.Ref.Thumbprint, newer.Ref.Thumbprint, older.Ref.Thumbprint)
	}

	// The stamp a caller gets back from Create is the stamp the store kept. These
	// disagreeing means the same key reports two different creation times depending on
	// which call you ask, and the sub-second half of the ordering above is a fiction.
	if !active.CreatedAt.Equal(newer.CreatedAt) {
		t.Errorf("Create stamped the key %s but List reads it back as %s — storage is "+
			"rounding the timestamp the key order depends on",
			newer.CreatedAt.Format(time.RFC3339Nano), active.CreatedAt.Format(time.RFC3339Nano))
	}
}

// Active answers "which key signs right now?", and the answer is a function of the
// validity window — not merely of which key is newest. A key whose window has closed,
// or has not yet opened, must never reach a signer: it would produce signatures that
// verifiers reject, and the agent's own published directory would say so.
func TestActiveIgnoresKeysWhoseWindowDoesNotCoverNow(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	expired, err := store.Create(ctx, agent, windowFrom(-48*time.Hour, 24*time.Hour))
	if err != nil {
		t.Fatalf("create the expired key: %v", err)
	}
	future, err := store.Create(ctx, agent, windowFrom(24*time.Hour, 24*time.Hour))
	if err != nil {
		t.Fatalf("create the not-yet-valid key: %v", err)
	}

	// The agent holds keys — two of them — and still has nothing it may sign with.
	// That is a different state from "this agent has never registered", and the
	// caller has to be able to tell them apart.
	if _, err := store.Active(ctx, agent); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("active = %v, want ErrNotFound: the agent holds keys, but none are in window", err)
	}

	// Out of window is not gone: both keys still publish, because a verifier holding
	// a cached signature made under the expired key still needs to resolve it.
	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 2 {
		t.Fatalf("the directory published %d keys, want both the expired and the future one", len(keys))
	}
	if !publishesKey(keys, expired.Ref) {
		t.Error("the expired key vanished from the directory")
	}
	if !publishesKey(keys, future.Ref) {
		t.Error("the not-yet-valid key vanished from the directory")
	}
}

// Newest-first is the ORDER Active searches in, not the RULE it applies. A key minted
// later but already out of window must lose to an older key that is still live — the
// case a rotation produces when a replacement is minted with a window that has already
// closed. Taking the first key off the listing would get this exactly wrong.
func TestActivePrefersTheLiveKeyOverANewerExpiredOne(t *testing.T) {
	store, clk := newStore(t)
	ctx := t.Context()

	live, err := store.Create(ctx, agent, windowFrom(0, 30*24*time.Hour))
	if err != nil {
		t.Fatalf("create the live key: %v", err)
	}

	// Minted an hour later, so it is newer by CreatedAt and leads the listing — but
	// its window closed a day before it was even created.
	clk.Advance(time.Hour)
	newerButExpired, err := store.Create(ctx, agent, windowFrom(-48*time.Hour, 24*time.Hour))
	if err != nil {
		t.Fatalf("create the newer expired key: %v", err)
	}

	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if keys[0].Ref != newerButExpired.Ref {
		t.Fatalf("the newest key does not lead the listing, so this test no longer arranges "+
			"the trap it exists to set: first key is %q", keys[0].Ref.Thumbprint)
	}

	active, err := store.Active(ctx, agent)
	if err != nil {
		t.Fatalf("active: %v", err)
	}
	if active.Ref != live.Ref {
		t.Errorf("signing key = %q, want the live key %q — Active took the newest key rather "+
			"than the newest LIVE one", active.Ref.Thumbprint, live.Ref.Thumbprint)
	}
}

// The window is half-open: valid when NotBefore <= t < NotAfter. Both ends are a
// decision, so both are asserted. A key that goes live an instant late, or signs an
// instant past its expiry, is a key whose signature and whose directory disagree.
func TestActiveHonoursTheHalfOpenWindowBoundaries(t *testing.T) {
	store, clk := newStore(t)
	ctx := t.Context()

	const life = 24 * time.Hour
	const opensIn = time.Hour

	key, err := store.Create(ctx, agent, windowFrom(opensIn, life))
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if _, err := store.Active(ctx, agent); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("active before NotBefore = %v, want ErrNotFound", err)
	}

	// Exactly NotBefore. The window is CLOSED at this end, so the key is live.
	clk.SetNow(anchor.Add(opensIn))
	active, err := store.Active(ctx, agent)
	if err != nil {
		t.Fatalf("active at exactly NotBefore = %v, want the key: the window includes its start", err)
	}
	if active.Ref != key.Ref {
		t.Errorf("active at NotBefore = %q, want %q", active.Ref.Thumbprint, key.Ref.Thumbprint)
	}

	// Exactly NotAfter. The window is OPEN at this end, so the key is already gone.
	clk.SetNow(anchor.Add(opensIn).Add(life))
	if _, err := store.Active(ctx, agent); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("active at exactly NotAfter = %v, want ErrNotFound: the window excludes its end", err)
	}
}

// A window that can never contain an instant describes a key that can never sign.
// Minting one would put a key in the agent's published directory that Active would
// never select and that no error would ever mention.
func TestCreateRejectsAWindowThatCanNeverBeActive(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	impossible := map[string]keystore.Window{
		"zero-width": {NotBefore: anchor, NotAfter: anchor},
		"inverted":   {NotBefore: anchor.Add(time.Hour), NotAfter: anchor},
	}
	for name, w := range impossible {
		t.Run("rejects a "+name+" window", func(t *testing.T) {
			if _, err := store.Create(ctx, agent, w); !errors.Is(err, keystore.ErrInvalidWindow) {
				t.Errorf("create with a %s window = %v, want ErrInvalidWindow", name, err)
			}
		})
	}

	// A rejected mint leaves nothing behind — same contract as a rejected subdomain.
	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 0 {
		t.Errorf("the agent holds %d keys after every mint was rejected", len(keys))
	}
}

// The developer owns the identity: an exported key must be usable somewhere else.
func TestExportedKeyCanBeReimportedAndStillSigns(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	key, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	exported, err := store.Export(ctx, key.Ref)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	reimported, err := pemkeys.ParseEd25519Private(exported)
	if err != nil {
		t.Fatalf("re-import the exported PEM: %v", err)
	}

	msg := []byte("signed after the developer moved to self-custody")
	if !ed25519.Verify(key.Public, msg, ed25519.Sign(reimported, msg)) {
		t.Error("the exported key does not sign for the identity it was exported from")
	}
}

// Custody must outlive the process holding it.
func TestKeysResolveThroughAFreshStoreOverTheSameVault(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	key, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	// A second store over the same Vault stands in for a restarted service: it
	// shares no memory with the first. It is built through the same helper as every
	// other store in the suite — the per-test reset already ran for this test, so
	// building a second store does not wipe the key the first one just wrote.
	restarted := newStoreWith(t, sharedVault.Client, sharedVault.Mount)

	recovered, err := restarted.Active(ctx, agent)
	if err != nil {
		t.Fatalf("active after restart: %v", err)
	}
	if recovered.Ref != key.Ref {
		t.Fatalf("recovered key %q, want %q", recovered.Ref.Thumbprint, key.Ref.Thumbprint)
	}
	if _, err := restarted.Signer(ctx, key.Ref); err != nil {
		t.Errorf("signer after restart: %v", err)
	}
}

// The keys List hands back are exactly the shape the agent's WBA directory
// publishes. Proving it here — rather than waiting for the ticket that builds the
// directory — is what makes "this backs the JWKS" a fact instead of an intention.
func TestListedKeysBuildAValidWBADirectory(t *testing.T) {
	store, clk := newStore(t)
	ctx := t.Context()

	older, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	clk.Advance(time.Hour)
	newer, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create second: %v", err)
	}

	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	jwks := make([]*rampwellknown.Key, 0, len(keys))
	for _, k := range keys {
		jwks = append(jwks, rampwellknown.NewKey(k.Public, k.Window.NotBefore, k.Window.NotAfter))
	}

	doc, err := wkserver.BuildWBA(wkserver.WBAConfig{Keys: wkserver.StaticKeys(jwks...)})
	if err != nil {
		t.Fatalf("the keys the store publishes do not form a valid WBA directory: %v", err)
	}

	// Assert the keys are IN the directory, not merely that building one succeeded.
	// An empty listing also builds a perfectly valid — and perfectly empty —
	// directory, so "no error" is a claim about the builder, not about custody: it
	// would stay green through exactly the bug that empties every agent's directory.
	//
	// A JWK carries the public key as its `x` member; the thumbprint is derived FROM
	// that, not printed beside it, so the published bytes are what a key's presence
	// looks like on the wire.
	body := string(doc)
	olderX, newerX := rampwellknown.EncodeEd25519X(older.Public), rampwellknown.EncodeEd25519X(newer.Public)
	for _, want := range []struct{ name, x string }{{"older", olderX}, {"newer", newerX}} {
		if !strings.Contains(body, want.x) {
			t.Errorf("the %s key (x=%q) is not in the published directory: %s",
				want.name, want.x, body)
		}
	}

	// And the newest leads. A WBA consumer resolving an identity without a known
	// thumbprint takes the first key in document order, so this order is what decides
	// which key its peers sign against — publishing the two in the wrong order would
	// silently hold everyone on the retired key through a rotation.
	if strings.Index(body, newerX) > strings.Index(body, olderX) {
		t.Errorf("the published directory leads with the OLDER key — a consumer taking the "+
			"first key in document order would keep signing against the retired one: %s", body)
	}
}

// One agent must never learn of another's keys — not even that they exist. A
// thumbprint is not a capability: presenting a valid one under the wrong
// subdomain is a miss, exactly as an unknown thumbprint is.
func TestAKeyIsInvisibleUnderAnotherAgentsSubdomain(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	victim, err := store.Create(ctx, "victim.rampmcp.org", liveWindow())
	if err != nil {
		t.Fatalf("create victim key: %v", err)
	}

	stolen := keystore.Ref{Subdomain: "attacker.rampmcp.org", Thumbprint: victim.Ref.Thumbprint}

	if _, err := store.Signer(ctx, stolen); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("signer with a borrowed thumbprint = %v, want ErrNotFound", err)
	}
	if _, err := store.Export(ctx, stolen); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("export with a borrowed thumbprint = %v, want ErrNotFound", err)
	}
	// And the victim's key is untouched by the attempts.
	if _, err := store.Signer(ctx, victim.Ref); err != nil {
		t.Errorf("the victim's key stopped working: %v", err)
	}
}

func TestUnknownKeyIsNotFound(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	// A well-formed thumbprint that was never minted.
	ref := keystore.Ref{
		Subdomain:  agent,
		Thumbprint: "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG",
	}
	if _, err := store.Signer(ctx, ref); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("signer = %v, want ErrNotFound", err)
	}
	if _, err := store.Active(ctx, "nobody.rampmcp.org"); !errors.Is(err, keystore.ErrNotFound) {
		t.Errorf("active for an agent with no keys = %v, want ErrNotFound", err)
	}

	// Listing an agent that holds no keys is a state, not a failure.
	keys, err := store.List(ctx, "nobody.rampmcp.org")
	if err != nil {
		t.Fatalf("list for an unknown agent = %v, want no error", err)
	}
	if len(keys) != 0 {
		t.Errorf("list for an unknown agent returned %d keys", len(keys))
	}
}

// A subdomain becomes part of a storage path, so a crafted one must be refused
// before it can reach Vault — and must leave no trace when it is.
func TestACraftedSubdomainIsRejectedAndWritesNothing(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	if _, err := store.Create(ctx, agent, liveWindow()); err != nil {
		t.Fatalf("create the legitimate key: %v", err)
	}

	for _, crafted := range []string{"../" + agent, agent + "/../other", "..", "/etc/passwd"} {
		if _, err := store.Create(ctx, crafted, liveWindow()); !errors.Is(err, keystore.ErrInvalidSubdomain) {
			t.Errorf("create(%q) = %v, want ErrInvalidSubdomain", crafted, err)
		}
		if _, err := store.List(ctx, crafted); !errors.Is(err, keystore.ErrInvalidSubdomain) {
			t.Errorf("list(%q) = %v, want ErrInvalidSubdomain", crafted, err)
		}
	}

	keys, err := store.List(ctx, agent)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(keys) != 1 {
		t.Errorf("the legitimate agent now holds %d keys, want 1 — a rejected subdomain still wrote something",
			len(keys))
	}
}

// Custody must fail closed. A store whose credential Vault rejects returns an
// error; it never returns a nil key that a caller might sign nothing with.
//
// And the error must say WHICH failure it is. "Some error happened" is not the
// guarantee: a rejected credential is ErrPermissionDenied, and if it ever came back
// as ErrUnavailable instead, a caller would retry a token Vault will refuse every
// time and page an operator for an outage that is not happening. Asserting only
// err != nil would let exactly that swap through unnoticed.
func TestAnUnauthenticatedStoreFailsClosed(t *testing.T) {
	store, _ := newStore(t)
	ctx := t.Context()

	good, err := store.Create(ctx, agent, liveWindow())
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	denied := newStoreWith(t, clientWithToken(t, "not-a-valid-token"), sharedVault.Mount)

	signer, sErr := denied.Signer(ctx, good.Ref)
	if !errors.Is(sErr, keystore.ErrPermissionDenied) {
		t.Errorf("signer with a rejected token = %v, want ErrPermissionDenied", sErr)
	}
	if signer != nil {
		t.Error("a failed lookup returned a non-nil signer")
	}
	if errors.Is(sErr, keystore.ErrNotFound) {
		t.Error("a rejected credential is reported as ErrNotFound — the store would look empty, not locked out")
	}
	if _, err := denied.Create(ctx, agent, liveWindow()); !errors.Is(err, keystore.ErrPermissionDenied) {
		t.Errorf("create with a rejected token = %v, want ErrPermissionDenied", err)
	}
}

// pureEd25519 is the SignerOpts Ed25519 requires when signing through the
// crypto.Signer interface: it signs the message itself rather than a digest, so
// the hash is explicitly none.
func pureEd25519() crypto.SignerOpts { return crypto.Hash(0) }

// publishesKey reports whether a listing carries ref — i.e. whether the agent's
// directory still publishes that key.
func publishesKey(keys []keystore.Key, ref keystore.Ref) bool {
	return slices.ContainsFunc(keys, func(k keystore.Key) bool { return k.Ref == ref })
}
