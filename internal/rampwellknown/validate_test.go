package rampwellknown_test

import (
	"bytes"
	"errors"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

// validJWK is a schema-conformant WBA JWK literal (x is 43 base64url chars, no kid).
const validJWK = `{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA",` +
	`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",` +
	`"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z"}`

func TestValidateManifest_ValidRoles(t *testing.T) {
	t.Parallel()
	// Overlay manifests are keyless after the WBA split; only ver/role/domain
	// are required for every role.
	cases := map[string]*rampwellknown.Manifest{
		"agent":    testutil.Manifest(rampwellknown.RoleAgent, "a.example"),
		"broker":   testutil.Manifest(rampwellknown.RoleBroker, "b.example"),
		"exchange": testutil.Manifest(rampwellknown.RoleExchange, "x.example"),
	}
	pub := testutil.Manifest(rampwellknown.RolePublisher, "p.example")
	pub.Exchanges = []*rampv1.AuthorizedExchange{
		testutil.PublisherExchange("x.example", "https://x.example/v1",
			rampv1.ProviderRelationship_PROVIDER_RELATIONSHIP_DIRECT),
	}
	cases["publisher"] = pub

	for name, m := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := rampwellknown.ValidateManifest(testutil.MarshalManifest(m)); err != nil {
				t.Fatalf("expected valid, got %v", err)
			}
		})
	}
}

// TestParseManifest_OverlayCannotCarryIdentityKeys pins the split's security
// intent from the consumer side: identity keys come ONLY from the WBA directory,
// never from the ramp.json overlay. A misconfigured or hostile overlay that
// carries public_keys / invalidation_url is accepted by the forward-compatible
// overlay schema, but the consumer drops those members (the typed overlay has no
// field for them), so no identity key is resolvable through the overlay parse
// surface. Verified by round-trip: the parsed manifest re-marshals with neither
// member present.
func TestParseManifest_OverlayCannotCarryIdentityKeys(t *testing.T) {
	t.Parallel()
	hostile := []byte(`{"ver":"1.0","role":"ROLE_AGENT","domain":"a.example",` +
		`"public_keys":[` + validJWK + `],"invalidation_url":"https://a.example/rev.json"}`)

	m, err := rampwellknown.ParseManifest(hostile, rampwellknown.RoleAgent)
	if err != nil {
		t.Fatalf("overlay with stray identity fields should parse (forward-compat), got %v", err)
	}
	round := testutil.MarshalManifest(m)
	if bytes.Contains(round, []byte("public_keys")) {
		t.Fatalf("parsed overlay must not carry public_keys; round-trip = %s", round)
	}
	if bytes.Contains(round, []byte("invalidation_url")) {
		t.Fatalf("parsed overlay must not carry invalidation_url; round-trip = %s", round)
	}
}

func TestValidateManifest_Rejections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		json string
	}{
		{"wrong ver", `{"ver":"0.3","role":"ROLE_AGENT","domain":"a"}`},
		{"unknown role", `{"ver":"1.0","role":"ROLE_FOO","domain":"a"}`},
		{"missing domain", `{"ver":"1.0","role":"ROLE_AGENT"}`},
		{
			"short relationship form rejected",
			`{"ver":"1.0","role":"ROLE_PUBLISHER","domain":"p","exchanges":[` +
				`{"domain":"x","endpoint":"https://x/v1","relationship":"DIRECT"}]}`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := rampwellknown.ValidateManifest([]byte(tc.json))
			if !errors.Is(err, rampwellknown.ErrSchemaInvalid) {
				t.Fatalf("want ErrSchemaInvalid, got %v", err)
			}
		})
	}
}

func TestValidateManifest_MinimalRolesAreValid(t *testing.T) {
	t.Parallel()
	// After the WBA split no role publishes keys in the overlay; a minimal
	// {ver,role,domain} manifest is valid for every role.
	for _, role := range []string{"ROLE_AGENT", "ROLE_BROKER", "ROLE_EXCHANGE", "ROLE_PUBLISHER"} {
		raw := []byte(`{"ver":"1.0","role":"` + role + `","domain":"p.example"}`)
		if err := rampwellknown.ValidateManifest(raw); err != nil {
			t.Fatalf("minimal %s manifest should validate: %v", role, err)
		}
	}
}

func TestValidateWBA(t *testing.T) {
	t.Parallel()
	good := []byte(`{"keys":[` + validJWK + `]}`)
	if err := rampwellknown.ValidateWBA(good); err != nil {
		t.Fatalf("valid WBA directory rejected: %v", err)
	}
	withRevocation := []byte(`{"keys":[` + validJWK + `],"revocation_url":"https://a.example/rev.json"}`)
	if err := rampwellknown.ValidateWBA(withRevocation); err != nil {
		t.Fatalf("valid WBA directory with revocation_url rejected: %v", err)
	}

	rejections := map[string]string{
		"empty keys":   `{"keys":[]}`,
		"missing keys": `{}`,
		"jwk carries no x": `{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA",` +
			`"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z"}]}`,
		"short x": `{"keys":[{"kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA","x":"tooshort",` +
			`"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z"}]}`,
	}
	for name, js := range rejections {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if err := rampwellknown.ValidateWBA([]byte(js)); !errors.Is(err, rampwellknown.ErrSchemaInvalid) {
				t.Fatalf("want ErrSchemaInvalid, got %v", err)
			}
		})
	}
}

func TestValidateRevocation(t *testing.T) {
	t.Parallel()
	good := testutil.MarshalRevocation(anchor, "revoked-thumbprint")
	if err := rampwellknown.ValidateRevocation(good); err != nil {
		t.Fatalf("valid revocation list rejected: %v", err)
	}
	// A "nothing revoked" snapshot serializes to just {as_of} (protojson omits
	// the empty repeated field); it MUST validate as an empty revocation set.
	empty := testutil.MarshalRevocation(anchor)
	if err := rampwellknown.ValidateRevocation(empty); err != nil {
		t.Fatalf("empty revocation list ({as_of} only) rejected: %v", err)
	}
	missingAsOf := `{"revoked":["tp1"]}`
	if err := rampwellknown.ValidateRevocation([]byte(missingAsOf)); !errors.Is(err, rampwellknown.ErrSchemaInvalid) {
		t.Fatalf("want ErrSchemaInvalid for missing as_of, got %v", err)
	}
}
