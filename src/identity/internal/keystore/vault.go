package keystore

import (
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/hashicorp/vault/api"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/pemkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// VaultStore is the KeyStore backed by HashiCorp Vault's KV v2 engine. Vault
// owns encryption at rest, the access-control check on every read, and the audit
// trail — so this type holds no key-encryption key and hand-rolls no crypto.
//
// A hazard for whoever implements revocation on top of this: KV v2 keeps a
// VERSION HISTORY. Overwriting a secret does NOT erase what was there before, so
// destroying a private key means explicitly destroying the versions that still
// hold it — a seedless new version leaves the old one, key and all, readable to
// anyone who can name a version number.
type VaultStore struct {
	kv     *api.KVv2
	client *api.Client
	mount  string
	prefix string
	clk    clock.Clock
}

// Compile-time proof that the Vault backend satisfies the custody port.
var _ KeyStore = (*VaultStore)(nil)

// NewVaultStore builds a store over an already-authenticated Vault client.
func NewVaultStore(cfg Config) (*VaultStore, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &VaultStore{
		kv:     cfg.Client.KVv2(cfg.Mount),
		client: cfg.Client,
		mount:  cfg.Mount,
		prefix: cfg.Prefix,
		clk:    cfg.Clk,
	}, nil
}

// Create mints a fresh Ed25519 keypair for subdomain, valid over w.
func (s *VaultStore) Create(ctx context.Context, subdomain string, w Window) (Key, error) {
	if err := validateSubdomain(subdomain); err != nil {
		return Key{}, err
	}
	if !w.NotBefore.Before(w.NotAfter) {
		return Key{}, fmt.Errorf("%w: not_before %s is not before not_after %s",
			ErrInvalidWindow, w.NotBefore.Format(time.RFC3339), w.NotAfter.Format(time.RFC3339))
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return Key{}, fmt.Errorf("%w: generate ed25519 key: %w", ErrInternal, err)
	}
	thumbprint, err := helpers.Thumbprint(pub)
	if err != nil {
		return Key{}, fmt.Errorf("%w: thumbprint: %w", ErrInternal, err)
	}
	ref := Ref{Subdomain: subdomain, Thumbprint: thumbprint}
	rec := record{
		seed:      priv.Seed(),
		public:    pub,
		window:    w,
		createdAt: s.clk.Now(),
	}
	if err := s.put(ctx, ref, rec); err != nil {
		return Key{}, err
	}
	return rec.key(ref), nil
}

// Active returns the newest key whose window covers the present instant.
func (s *VaultStore) Active(ctx context.Context, subdomain string) (Key, error) {
	keys, err := s.List(ctx, subdomain)
	if err != nil {
		return Key{}, err
	}
	now := s.clk.Now()
	for _, k := range keys {
		if !now.Before(k.Window.NotBefore) && now.Before(k.Window.NotAfter) {
			return k, nil
		}
	}
	return Key{}, fmt.Errorf("%w: no active key for %q", ErrNotFound, subdomain)
}

// Signer returns a signer for ref. The KV backend can hand back the key itself,
// which already satisfies crypto.Signer; a Transit or HSM backend would return a
// remote signer here instead, and no caller would notice.
//
// It signs with the key it is ASKED for and does not consult that key's validity
// window: selecting the key that should sign now is Active's job, and a Signer that
// second-guessed an explicit Ref would make it impossible to sign with a key whose
// window has closed — which is precisely what a caller re-signing or re-verifying a
// past request needs to do. A caller that wants the current key asks Active for it.
func (s *VaultStore) Signer(ctx context.Context, ref Ref) (crypto.Signer, error) {
	rec, err := s.get(ctx, ref)
	if err != nil {
		return nil, err
	}
	priv, err := rec.private()
	if err != nil {
		return nil, err
	}
	return priv, nil
}

// List returns every key held for subdomain, newest first. An agent with no keys
// yields an empty slice, not an error: holding no key yet is a state, not a failure.
// A misconfigured mount, by contrast, is an error — see rawRead.
func (s *VaultStore) List(ctx context.Context, subdomain string) ([]Key, error) {
	if err := validateSubdomain(subdomain); err != nil {
		return nil, err
	}
	thumbprints, err := s.thumbprints(ctx, subdomain)
	if err != nil {
		return nil, err
	}
	keys := make([]Key, 0, len(thumbprints))
	for _, tp := range thumbprints {
		ref := Ref{Subdomain: subdomain, Thumbprint: tp}
		rec, err := s.get(ctx, ref)
		if err != nil {
			// A key that vanished between the listing and the read — deleted by an
			// operator, expired by a retention policy — is not an error for the caller;
			// anything else is. It is still worth a line in the log: an agent's published
			// directory quietly losing a key is exactly the kind of thing nobody notices
			// until a verifier starts rejecting signatures.
			if errors.Is(err, ErrNotFound) {
				// The logger comes off the context, not off the store: that is what carries
				// the request_id, and a line nobody can tie back to the request that
				// produced it is the one line an operator cannot act on.
				reqctx.FromContext(ctx).WarnContext(ctx,
					"key vanished between listing and read; omitting it from the agent's directory",
					"subdomain", subdomain, "thumbprint", tp)
				continue
			}
			return nil, err
		}
		keys = append(keys, rec.key(ref))
	}
	sortNewestFirst(keys)
	return keys, nil
}

// Export returns ref's private key as a PKCS#8 PEM document.
func (s *VaultStore) Export(ctx context.Context, ref Ref) ([]byte, error) {
	rec, err := s.get(ctx, ref)
	if err != nil {
		return nil, err
	}
	priv, err := rec.private()
	if err != nil {
		return nil, err
	}
	pemBytes, err := pemkeys.MarshalEd25519Private(priv)
	if err != nil {
		return nil, fmt.Errorf("%w: export %s: %w", ErrInternal, ref.Thumbprint, err)
	}
	return pemBytes, nil
}

// Expire shortens ref's validity window to end at notAfter. It reads the record,
// checks that the new bound only ever moves the window's end INWARD, and writes the
// record back with the shortened window — the seed, the public half and CreatedAt
// ride along unchanged, so the key keeps its identity and its place in the order.
//
// The read-modify-write is not a transaction, and it does not need to be here: the
// only caller is the single rotation loop, which retires a given key once. A window
// already ending exactly at notAfter is left untouched — nothing to write — so a
// retried retirement is a no-op rather than a spurious new version.
func (s *VaultStore) Expire(ctx context.Context, ref Ref, notAfter time.Time) error {
	rec, err := s.get(ctx, ref)
	if err != nil {
		return err
	}
	notAfter = notAfter.UTC()
	if !notAfter.After(rec.window.NotBefore) {
		return fmt.Errorf("%w: not_after %s is not after not_before %s",
			ErrInvalidWindow, notAfter.Format(time.RFC3339), rec.window.NotBefore.Format(time.RFC3339))
	}
	if notAfter.After(rec.window.NotAfter) {
		return fmt.Errorf("%w: not_after %s would extend the window past %s; Expire only shortens",
			ErrInvalidWindow, notAfter.Format(time.RFC3339), rec.window.NotAfter.Format(time.RFC3339))
	}
	if notAfter.Equal(rec.window.NotAfter) {
		return nil
	}
	rec.window.NotAfter = notAfter
	if err := s.put(ctx, ref, rec); err != nil {
		return err
	}
	return nil
}

// Destroy permanently erases every version of ref's key material via a KV v2
// delete-metadata, which drops the secret's metadata AND all its versions in one
// call. A plain Put would only add a new version and leave the seed sitting in the
// old one; delete-metadata is the operation that actually closes that leak.
//
// Deleting a path that holds nothing is a success on Vault's side, so this is
// idempotent: re-running a revocation whose first attempt died after the list write
// but before the erase simply completes the erase. validateRef still runs first, so
// a malformed ref is rejected before it can name a storage path.
func (s *VaultStore) Destroy(ctx context.Context, ref Ref) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	if err := s.kv.DeleteMetadata(ctx, s.secretPath(ref)); err != nil {
		return classify("destroy key", err)
	}
	return nil
}

// get reads and parses one key record.
//
// It reads the raw KV path rather than the api.KVv2 helper for the same reason
// rawRead exists at all: the helper collapses EVERY 404 into "no such secret",
// including the one Vault returns for a path whose MOUNT does not exist. A store
// built on it answers "this agent holds no such key" when the truth is "this
// deployment has no key store" — so a signing request against a misconfigured mount
// reads as a caller naming a key that never existed, and nobody goes looking for the
// mount. The two 404s are told apart here, where Vault still distinguishes them.
func (s *VaultStore) get(ctx context.Context, ref Ref) (record, error) {
	if err := validateRef(ref); err != nil {
		return record{}, err
	}
	secret, err := s.rawRead(ctx, s.dataReadPath(ref), nil)
	if err != nil {
		return record{}, classify("read key", err)
	}
	if secret == nil {
		return record{}, fmt.Errorf("%w: %s/%s", ErrNotFound, ref.Subdomain, ref.Thumbprint)
	}
	data, err := kvData(secret)
	if err != nil {
		return record{}, err
	}
	// A KV v2 delete is a SOFT delete: the secret survives with its data emptied,
	// and Vault reports a perfectly successful read. To the store a key whose data is
	// gone is a key that is gone — reading it as a malformed record would blame the
	// storage format for what is really an absent key.
	if len(data) == 0 {
		return record{}, fmt.Errorf("%w: %s/%s", ErrNotFound, ref.Subdomain, ref.Thumbprint)
	}
	rec, err := parseRecord(data)
	if err != nil {
		return record{}, err
	}
	return rec, nil
}

// kvData unwraps the KV v2 read envelope, which nests the record's fields under a
// "data" key alongside its version metadata. A soft-deleted secret carries a null
// there, which is an absent key rather than a malformed one; anything that is
// neither null nor an object is a payload the store cannot trust.
func kvData(secret *api.Secret) (map[string]any, error) {
	raw, ok := secret.Data["data"]
	if !ok || raw == nil {
		return nil, nil
	}
	data, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: vault returned a %T where the record's fields belong", ErrCorrupt, raw)
	}
	return data, nil
}

// put writes one key record, failing if Vault does not confirm the write with
// version metadata — a write Vault did not version is one this store cannot trust.
func (s *VaultStore) put(ctx context.Context, ref Ref, rec record) error {
	if err := validateRef(ref); err != nil {
		return err
	}
	secret, err := s.kv.Put(ctx, s.secretPath(ref), rec.data())
	if err != nil {
		return classify("write key", err)
	}
	if secret == nil || secret.VersionMetadata == nil {
		return fmt.Errorf("%w: write key %s: vault returned no version metadata",
			ErrInternal, ref.Thumbprint)
	}
	return nil
}

// ListSubdomains returns every subdomain that holds at least one key. See
// KeyStore.ListSubdomains. It LISTs the agents prefix itself — one level above the
// per-agent listing thumbprints uses — through the same raw read, so a missing mount
// is told apart from an empty store here exactly as it is everywhere else.
func (s *VaultStore) ListSubdomains(ctx context.Context) ([]string, error) {
	secret, err := s.rawRead(ctx, s.metadataListPath(""), listParams)
	if err != nil {
		return nil, classify("list subdomains", err)
	}
	return parseSubdomains(secret)
}

// listEntries unwraps a Vault LIST payload's "keys" field into its raw entries, telling
// an empty listing (a nil secret — the path is real but holds nothing) apart from a
// corrupt one the store must never read as an empty set. label names the listed path
// for the error message. parseSubdomains and parseThumbprints share this envelope and
// differ only in the per-entry filter each applies to the result.
func listEntries(secret *api.Secret, label string) ([]any, error) {
	if secret == nil {
		return nil, nil // the path is real and holds nothing
	}
	raw, ok := secret.Data["keys"]
	if !ok {
		return nil, fmt.Errorf("%w: vault's listing of %s carries no keys field", ErrCorrupt, label)
	}
	entries, ok := raw.([]any)
	if !ok {
		return nil, fmt.Errorf("%w: vault listed %s as a %T", ErrCorrupt, label, raw)
	}
	return entries, nil
}

// parseSubdomains reads the subdomains out of a Vault LIST of the agents prefix. Each
// entry is a folder holding one agent's key secrets, so Vault returns it with a
// trailing slash; the slash is stripped and the name validated against the grammar
// every entry point enforces, so anything under the prefix that is not a well-formed
// agent namespace is skipped rather than mistaken for one. Split out from
// ListSubdomains, and taking the parsed secret, so the corrupt-payload branches are
// reachable from a plain unit test — the same reasoning as parseThumbprints.
func parseSubdomains(secret *api.Secret) ([]string, error) {
	entries, err := listEntries(secret, "the agents prefix")
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		name, ok := entry.(string)
		if !ok {
			continue
		}
		name = strings.TrimSuffix(name, "/")
		if validateSubdomain(name) != nil {
			continue // not an agent namespace; never let it become a storage path
		}
		out = append(out, name)
	}
	return out, nil
}

// thumbprints lists the keys an agent holds.
func (s *VaultStore) thumbprints(ctx context.Context, subdomain string) ([]string, error) {
	secret, err := s.rawRead(ctx, s.metadataListPath(subdomain), listParams)
	if err != nil {
		return nil, classify(fmt.Sprintf("list keys of %q", subdomain), err)
	}
	return parseThumbprints(secret, subdomain)
}

// parseThumbprints reads the thumbprints out of a Vault LIST payload. An agent with
// no keys yields none; a payload the store cannot read is ErrCorrupt, NOT an empty
// list. Reporting a payload it failed to understand as "this agent holds no keys" is
// the same silent-empty-directory failure the rest of this file exists to prevent —
// it would just arrive through the parser instead of through the mount.
//
// It is split out from thumbprints, and takes the parsed secret rather than reaching
// for Vault itself, so that the corrupt-payload branches are reachable from a plain
// unit test. A real Vault will not serve a malformed listing on request, and mocking
// the backend to force one is forbidden here — so the alternative to a pure function
// is a guarantee with no test behind it.
func parseThumbprints(secret *api.Secret, subdomain string) ([]string, error) {
	entries, err := listEntries(secret, fmt.Sprintf("the keys of %q", subdomain))
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(entries))
	for _, entry := range entries {
		tp, ok := entry.(string)
		if !ok || !thumbprintRE.MatchString(tp) {
			continue // not a key record of ours; never let it become a read path
		}
		out = append(out, tp)
	}
	return out, nil
}

// listParams turns a Vault GET into a LIST.
var listParams = map[string][]string{"list": {"true"}}

// rawRead issues a raw Vault GET and distinguishes "this path holds nothing" from
// "this path does not exist". Every read and every listing in this store goes
// through it, so the distinction cannot hold on one path and lapse on another.
//
// That distinction is invisible through the client's convenience wrappers —
// Logical().List and KVv2.Get alike — which collapse EVERY 404, including the one
// Vault returns for an unmounted path, into an empty result. A store built on them
// would answer "this agent holds no keys" for every agent in the system whenever the
// KV mount was misconfigured, publish empty directories, and look perfectly healthy
// while doing so. Vault itself does draw the line: an empty-but-real path 404s with
// no errors, an unmounted path 404s naming the route it could not find. So the raw
// response is read here rather than the convenience wrapper that throws that away.
func (s *VaultStore) rawRead(ctx context.Context, path string, params map[string][]string) (*api.Secret, error) {
	resp, err := s.client.Logical().ReadRawWithDataWithContext(ctx, path, params)
	if resp != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		var respErr *api.ResponseError
		if errors.As(err, &respErr) &&
			respErr.StatusCode == http.StatusNotFound && len(respErr.Errors) == 0 {
			return nil, nil // the path is real and holds nothing
		}
		return nil, err
	}
	return api.ParseSecret(resp.Body)
}

// classify turns a Vault client error into one of the store's sentinels, at the one
// point where what went wrong is still known.
//
// Detecting a failure loudly is only half of custody's job: a caller that cannot
// tell an outage from a denial cannot act on either. Retry the outage, page an
// operator for the denial — and to choose, a caller would otherwise have to import
// the Vault SDK and type-assert its way to the status code, which is precisely the
// backend leak the KeyStore interface exists to prevent. So the classification
// happens here, in the adapter, and callers branch on the condition instead.
//
// A context error is the caller's own cancellation, not a fault of the backend, so
// it is not blamed on Vault — paging somebody for an outage because a client hung up
// helps nobody. It still carries ErrInternal, because EVERY error leaving this
// package carries a sentinel: a transport mapping domain errors onto connect.Code
// needs a total mapping, and a residual class is what makes it total.
func classify(op string, err error) error {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%w: %s: %w", ErrInternal, op, err)
	}
	var respErr *api.ResponseError
	if errors.As(err, &respErr) {
		switch {
		case respErr.StatusCode == http.StatusUnauthorized, respErr.StatusCode == http.StatusForbidden:
			return fmt.Errorf("%w: %s: %w", ErrPermissionDenied, op, err)
		case respErr.StatusCode == http.StatusNotFound:
			// Not a missing secret — rawRead maps that to a nil result, and get turns it
			// into ErrNotFound, before it ever gets here. A 404 that survives to this point
			// named a route Vault could not find: the mount is not there. That is a
			// misconfigured deployment, and it must never read as "this agent holds no keys".
			return fmt.Errorf("%w: %s: vault has no such mount: %w", ErrUnavailable, op, err)
		case respErr.StatusCode == http.StatusTooManyRequests,
			respErr.StatusCode >= http.StatusInternalServerError:
			return fmt.Errorf("%w: %s: %w", ErrUnavailable, op, err)
		}
		// Every other status Vault can return (400, 409, 412 …) means this store built a
		// request wrong. No retry fixes it and no operator policy does either, so it is
		// neither unavailable nor denied — it is this package's own bug.
		return fmt.Errorf("%w: %s: %w", ErrInternal, op, err)
	}
	// No HTTP response at all — connection refused, TLS failure, EOF. The backend is
	// not answering, which is what unavailable means.
	return fmt.Errorf("%w: %s: %w", ErrUnavailable, op, err)
}

// sortNewestFirst orders keys by CreatedAt descending, ties broken by thumbprint
// so the order is total and stable. The order is what a WBA consumer resolving an
// identity by document order depends on: the newest key must lead, or a rotation
// would leave peers signing against the old one.
func sortNewestFirst(keys []Key) {
	slices.SortStableFunc(keys, func(a, b Key) int {
		if c := b.CreatedAt.Compare(a.CreatedAt); c != 0 {
			return c
		}
		return strings.Compare(a.Ref.Thumbprint, b.Ref.Thumbprint)
	})
}
