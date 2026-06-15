package rampwellknown_test

import (
	"errors"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

// validJWK is a schema-conformant JWK literal (x is 43 base64url chars).
const validJWK = `{"kid":"k","kty":"OKP","crv":"Ed25519","use":"sig","alg":"EdDSA",` +
	`"x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo",` +
	`"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z"}`

func TestValidateManifest_ValidRoles(t *testing.T) {
	t.Parallel()
	_, key := testutil.NewSigningKey("k", anchor, anchor.Add(time.Hour))
	cases := map[string]*rampwellknown.Manifest{
		"agent":    testutil.Manifest(rampwellknown.RoleAgent, "a.example", key),
		"broker":   testutil.Manifest(rampwellknown.RoleBroker, "b.example", key),
		"exchange": testutil.Manifest(rampwellknown.RoleExchange, "x.example", key),
	}
	pub := testutil.Manifest(rampwellknown.RolePublisher, "p.example", key)
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

func TestValidateManifest_Rejections(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		json string
	}{
		{"wrong ver", `{"ver":"0.3","role":"ROLE_AGENT","domain":"a","public_keys":[` + validJWK + `]}`},
		{"unknown role", `{"ver":"1.0","role":"ROLE_FOO","domain":"a","public_keys":[` + validJWK + `]}`},
		{"agent missing public_keys", `{"ver":"1.0","role":"ROLE_AGENT","domain":"a"}`},
		{"missing domain", `{"ver":"1.0","role":"ROLE_AGENT","public_keys":[` + validJWK + `]}`},
		{
			"short x",
			`{"ver":"1.0","role":"ROLE_AGENT","domain":"a","public_keys":[{"kid":"k","kty":"OKP",` +
				`"crv":"Ed25519","use":"sig","alg":"EdDSA","x":"tooshort",` +
				`"not_before":"2026-01-01T00:00:00Z","not_after":"2027-01-01T00:00:00Z"}]}`,
		},
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

func TestValidateManifest_MinimalPublisherIsValid(t *testing.T) {
	t.Parallel()
	// A publisher MAY omit public_keys and exchanges (authorizes out of band /
	// issues no attestations); only ver/role/domain are required.
	raw := []byte(`{"ver":"1.0","role":"ROLE_PUBLISHER","domain":"p.example"}`)
	if err := rampwellknown.ValidateManifest(raw); err != nil {
		t.Fatalf("minimal publisher manifest should validate: %v", err)
	}
}

func TestValidateInvalidation(t *testing.T) {
	t.Parallel()
	good := testutil.MarshalInvalidation(anchor, "revoked-kid")
	if err := rampwellknown.ValidateInvalidation(good); err != nil {
		t.Fatalf("valid invalidation list rejected: %v", err)
	}
	// A "nothing revoked" snapshot serializes to just {as_of} (protojson omits
	// the empty repeated field); it MUST validate as an empty revocation set.
	empty := testutil.MarshalInvalidation(anchor)
	if err := rampwellknown.ValidateInvalidation(empty); err != nil {
		t.Fatalf("empty invalidation list ({as_of} only) rejected: %v", err)
	}
	missingAsOf := `{"revoked":["k1"]}`
	if err := rampwellknown.ValidateInvalidation([]byte(missingAsOf)); !errors.Is(err, rampwellknown.ErrSchemaInvalid) {
		t.Fatalf("want ErrSchemaInvalid for missing as_of, got %v", err)
	}
}
