package keystore

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// Pure-logic tests for the stored record: the format that outlives the process,
// and the integrity check that stands between a corrupt record and a signature
// nobody can verify. No Vault here — these exercise encode/decode and the crypto,
// which is what the testing doctrine permits a unit test to cover.

func newTestRecord(t *testing.T) (record, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	now := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	return record{
		seed:      priv.Seed(),
		public:    pub,
		window:    Window{NotBefore: now, NotAfter: now.Add(30 * 24 * time.Hour)},
		createdAt: now,
	}, pub
}

func TestRecordSurvivesTheRoundTripThroughVaultsPayload(t *testing.T) {
	t.Parallel()

	original, pub := newTestRecord(t)

	parsed, err := parseRecord(original.data())
	if err != nil {
		t.Fatalf("parse record: %v", err)
	}

	if !parsed.public.Equal(pub) {
		t.Error("public key did not survive the round trip")
	}
	if !parsed.window.NotAfter.Equal(original.window.NotAfter) {
		t.Errorf("not_after = %s, want %s", parsed.window.NotAfter, original.window.NotAfter)
	}
	if !parsed.createdAt.Equal(original.createdAt) {
		t.Errorf("created_at = %s, want %s", parsed.createdAt, original.createdAt)
	}

	priv, err := parsed.private()
	if err != nil {
		t.Fatalf("recover private key: %v", err)
	}
	msg := []byte("signed with the key recovered from storage")
	if !ed25519.Verify(pub, msg, ed25519.Sign(priv, msg)) {
		t.Error("the recovered key produces a signature its own public half rejects")
	}
}

// The seed and the public key are stored side by side, so a record can contradict
// itself — a bad restore, a hand-edited secret, a mismatched write. Signing with
// such a record would emit signatures no verifier accepts, and it would do so
// silently, so the store refuses instead.
func TestPrivateRejectsARecordWhoseSeedDoesNotDeriveItsPublicKey(t *testing.T) {
	t.Parallel()

	rec, _ := newTestRecord(t)
	otherPub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	rec.public = otherPub // the seed now belongs to a different key

	if _, err := rec.private(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("private() error = %v, want ErrCorrupt", err)
	}
}

func TestPrivateRejectsATruncatedSeed(t *testing.T) {
	t.Parallel()

	rec, _ := newTestRecord(t)
	rec.seed = rec.seed[:16]

	if _, err := rec.private(); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("private() error = %v, want ErrCorrupt", err)
	}
}

func TestParseRecordRejectsMalformedPayloads(t *testing.T) {
	t.Parallel()

	valid, _ := newTestRecord(t)

	tests := map[string]func(map[string]any){
		"public key missing":     func(d map[string]any) { delete(d, fieldPublic) },
		"created_at missing":     func(d map[string]any) { delete(d, fieldCreatedAt) },
		"public key undecodable": func(d map[string]any) { d[fieldPublic] = "!!not base64url!!" },
		"not_after unparseable":  func(d map[string]any) { d[fieldNotAfter] = "yesterday" },
		"seed undecodable":       func(d map[string]any) { d[fieldSeed] = "!!not base64!!" },
		"seed missing":           func(d map[string]any) { delete(d, fieldSeed) },
	}
	for name, corrupt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			d := valid.data()
			corrupt(d)
			if _, err := parseRecord(d); !errors.Is(err, ErrCorrupt) {
				t.Fatalf("parseRecord error = %v, want ErrCorrupt", err)
			}
		})
	}
}

// The KV v2 read envelope nests the record's fields under "data". A soft-deleted
// secret carries a null there — an absent key, which the store reports as a miss.
// Anything else is a payload the store cannot trust, and it must say so rather than
// treat it as an empty record: "I could not read this" and "there is nothing here"
// are the two answers this package works hardest to keep apart.
func TestKVDataTellsASoftDeleteApartFromAMalformedEnvelope(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		data    map[string]any
		wantErr error
		wantLen int
	}{
		{"a live secret", map[string]any{"data": map[string]any{"seed": "x"}}, nil, 1},
		{"a soft-deleted secret", map[string]any{"data": nil}, nil, 0},
		{"an envelope with no data field", map[string]any{"metadata": map[string]any{}}, nil, 0},
		{"data that is not an object", map[string]any{"data": "not-an-object"}, ErrCorrupt, 0},
		{"data that is a list", map[string]any{"data": []any{"seed"}}, ErrCorrupt, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := kvData(&api.Secret{Data: tc.data})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("kvData(%v) error = %v, want %v", tc.data, err, tc.wantErr)
			}
			if len(got) != tc.wantLen {
				t.Errorf("kvData(%v) returned %d fields, want %d", tc.data, len(got), tc.wantLen)
			}
		})
	}
}

// A listing the store cannot read must be ErrCorrupt, never an empty key set. The
// two are worlds apart to a caller: "this agent holds no keys" publishes an empty
// directory and looks healthy, which is the exact failure the mount handling exists
// to prevent — it would just arrive through the parser instead.
//
// Vault will not serve a malformed listing on request, and mocking the backend to
// force one is forbidden here, so the parsing is a pure function and this is a plain
// unit test. The alternative was a guarantee with no test behind it.
func TestParseThumbprintsRefusesAListingItCannotRead(t *testing.T) {
	t.Parallel()

	const tp = "Zir3ApCpkch3UNfXEt8qtjS61MS39FRRfqYxD3cc4yw" // a well-formed thumbprint

	for _, tc := range []struct {
		name    string
		secret  *api.Secret
		wantErr error
		want    []string
	}{
		{
			name:   "an agent whose path holds nothing",
			secret: nil, // rawRead maps an empty-but-real path to nil
			want:   nil,
		},
		{
			name:   "a listing of one key",
			secret: &api.Secret{Data: map[string]any{"keys": []any{tp}}},
			want:   []string{tp},
		},
		{
			name:   "entries that are not thumbprints of ours are skipped, not read",
			secret: &api.Secret{Data: map[string]any{"keys": []any{tp, "../escape", 42}}},
			want:   []string{tp},
		},
		{
			name:    "a listing with no keys field at all",
			secret:  &api.Secret{Data: map[string]any{"something-else": 1}},
			wantErr: ErrCorrupt,
		},
		{
			name:    "a keys field that is not a list",
			secret:  &api.Secret{Data: map[string]any{"keys": "not-a-list"}},
			wantErr: ErrCorrupt,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseThumbprints(tc.secret, "agent-1.rampmcp.org")
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("parseThumbprints error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil && got != nil {
				t.Errorf("a refused listing still yielded %v — it must not read as an empty store", got)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("parseThumbprints = %v, want %v", got, tc.want)
			}
		})
	}
}

// parseSubdomains shares the LIST-envelope parser (listEntries) with parseThumbprints,
// so the same "a listing the store cannot read is ErrCorrupt, never an empty set"
// guarantee must hold for the agents-prefix listing that drives rotation's
// ListSubdomains — an empty read there would silently hide every agent from rotation.
func TestParseSubdomainsRefusesAListingItCannotRead(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name    string
		secret  *api.Secret
		wantErr error
		want    []string
	}{
		{
			name:   "a prefix that holds nothing",
			secret: nil, // rawRead maps an empty-but-real path to nil
			want:   nil,
		},
		{
			name:   "a listing of one agent folder (trailing slash stripped)",
			secret: &api.Secret{Data: map[string]any{"keys": []any{"agent-1.rampmcp.org/"}}},
			want:   []string{"agent-1.rampmcp.org"},
		},
		{
			name:   "entries that are not agent namespaces are skipped, not returned",
			secret: &api.Secret{Data: map[string]any{"keys": []any{"agent-1.rampmcp.org/", "../escape/", 42}}},
			want:   []string{"agent-1.rampmcp.org"},
		},
		{
			name:    "a listing with no keys field at all",
			secret:  &api.Secret{Data: map[string]any{"something-else": 1}},
			wantErr: ErrCorrupt,
		},
		{
			name:    "a keys field that is not a list",
			secret:  &api.Secret{Data: map[string]any{"keys": "not-a-list"}},
			wantErr: ErrCorrupt,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := parseSubdomains(tc.secret)
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("parseSubdomains error = %v, want %v", err, tc.wantErr)
			}
			if tc.wantErr != nil && got != nil {
				t.Errorf("a refused listing still yielded %v — it must not read as an empty store", got)
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("parseSubdomains = %v, want %v", got, tc.want)
			}
		})
	}
}

// The stored public key uses the same base64url encoding the WBA directory
// publishes, so a key can go from storage to JWKS without a second encoder.
func TestStoredPublicKeyUsesTheJWKEncoding(t *testing.T) {
	t.Parallel()

	rec, pub := newTestRecord(t)

	got, ok := rec.data()[fieldPublic].(string)
	if !ok {
		t.Fatal("public field is not a string")
	}
	if want := rampwellknown.EncodeEd25519X(pub); got != want {
		t.Errorf("stored public = %q, want the JWK x encoding %q", got, want)
	}
}
