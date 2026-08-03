package keystore

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// Field names of a stored key record. Everything lives inside the Vault secret's
// data — the seed alongside its metadata — so one key is one record with one
// lifecycle, and reading the metadata never means reading it from somewhere the
// secret is not.
const (
	fieldRecordVersion = "record_version"
	fieldSeed          = "seed"
	fieldPublic        = "public"
	fieldNotBefore     = "not_before"
	fieldNotAfter      = "not_after"
	fieldCreatedAt     = "created_at"
)

// recordVersion is stamped on every record so a future format change — the
// lifecycle fields rotation and revocation will add, for instance — can be
// migrated rather than guessed at.
const recordVersion = "1"

// record is one stored key: the secret half plus the metadata that describes it.
type record struct {
	seed      []byte
	public    ed25519.PublicKey
	window    Window
	createdAt time.Time
}

// data renders the record as a Vault KV v2 secret payload. The seed is base64
// standard (Vault stores JSON strings); the public key uses the JWK base64url
// encoding so it is already in the form the WBA directory publishes.
//
// Timestamps are RFC3339Nano, NOT RFC3339: the latter has no fractional-second
// field, so it would round every stamp to the whole second on the way out. Two keys
// minted for one agent inside the same second would then come back with identical
// CreatedAt values, sortNewestFirst would fall through to its thumbprint tie-break —
// which has nothing to do with when a key was made — and Active, taking the first
// live key off that listing, could hand back the OLDER of the two. The order this
// store publishes is load-bearing (see List), and a format that cannot represent it
// is not a place to save six characters. The read side parses either form, so a
// record written in the whole-second format still loads.
func (r record) data() map[string]any {
	return map[string]any{
		fieldRecordVersion: recordVersion,
		fieldSeed:          base64.StdEncoding.EncodeToString(r.seed),
		fieldPublic:        rampwellknown.EncodeEd25519X(r.public),
		fieldNotBefore:     r.window.NotBefore.UTC().Format(time.RFC3339Nano),
		fieldNotAfter:      r.window.NotAfter.UTC().Format(time.RFC3339Nano),
		fieldCreatedAt:     r.createdAt.UTC().Format(time.RFC3339Nano),
	}
}

// parseRecord reads a Vault secret payload back into a record.
func parseRecord(d map[string]any) (record, error) {
	pubX, err := stringField(d, fieldPublic)
	if err != nil {
		return record{}, err
	}
	pub, err := rampwellknown.DecodeEd25519X(pubX)
	if err != nil {
		return record{}, fmt.Errorf("%w: public key: %w", ErrCorrupt, err)
	}
	notBefore, err := timeField(d, fieldNotBefore)
	if err != nil {
		return record{}, err
	}
	notAfter, err := timeField(d, fieldNotAfter)
	if err != nil {
		return record{}, err
	}
	createdAt, err := timeField(d, fieldCreatedAt)
	if err != nil {
		return record{}, err
	}
	seed, err := decodeSeed(d)
	if err != nil {
		return record{}, err
	}
	return record{
		seed:      seed,
		public:    pub,
		window:    Window{NotBefore: notBefore, NotAfter: notAfter},
		createdAt: createdAt,
	}, nil
}

// key projects the record's public face — what List, Create and Active return.
func (r record) key(ref Ref) Key {
	return Key{
		Ref:       ref,
		Public:    r.public,
		Window:    r.window,
		CreatedAt: r.createdAt,
	}
}

// private reconstructs the Ed25519 private key from the stored seed and checks
// that it really derives the public key stored beside it. The check is free and it
// is the reason the SEED is stored rather than the 64-byte private key (half of
// which is the public key anyway): a record whose halves disagree would otherwise
// sign with a key nobody can verify, and would do so silently.
func (r record) private() (ed25519.PrivateKey, error) {
	if len(r.seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("%w: seed is %d bytes, want %d", ErrCorrupt, len(r.seed), ed25519.SeedSize)
	}
	priv := ed25519.NewKeyFromSeed(r.seed)
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, r.public) {
		return nil, fmt.Errorf("%w: stored seed does not derive the stored public key", ErrCorrupt)
	}
	return priv, nil
}

func stringField(d map[string]any, name string) (string, error) {
	raw, ok := d[name]
	if !ok {
		return "", fmt.Errorf("%w: field %q missing", ErrCorrupt, name)
	}
	s, ok := raw.(string)
	if !ok {
		return "", fmt.Errorf("%w: field %q is %T, want string", ErrCorrupt, name, raw)
	}
	return s, nil
}

func timeField(d map[string]any, name string) (time.Time, error) {
	s, err := stringField(d, name)
	if err != nil {
		return time.Time{}, err
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: field %q: %w", ErrCorrupt, name, err)
	}
	return t.UTC(), nil
}

func decodeSeed(d map[string]any) ([]byte, error) {
	s, err := stringField(d, fieldSeed)
	if err != nil {
		return nil, err
	}
	seed, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("%w: field %q: %w", ErrCorrupt, fieldSeed, err)
	}
	return seed, nil
}
