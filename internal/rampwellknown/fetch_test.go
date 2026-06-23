package rampwellknown_test

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

func TestFetch_HappyPathAssertsRole(t *testing.T) {
	t.Parallel()
	_, key := testutil.NewSigningKey("k", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	origin := testutil.NewOrigin(testutil.MarshalManifest(
		testutil.Manifest(rampwellknown.RoleAgent, "agent.example", key),
	))
	defer origin.Close()

	m, err := rampwellknown.Fetch(context.Background(), origin.URL, rampwellknown.FetchOptions{
		Client:     testutil.Client(),
		ExpectRole: rampwellknown.RoleAgent,
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if m.GetDomain() != "agent.example" || m.GetRole() != rampwellknown.RoleAgent {
		t.Fatalf("unexpected manifest: domain=%s role=%s", m.GetDomain(), m.GetRole())
	}
}

// TestFetch_ZeroClientUsesGuardedDefault pins that omitting Client falls back to
// the SSRF-guarded env client (not http.DefaultClient): with
// RAMP_FETCH_INSECURE_ALLOW_PRIVATE unset it rejects the http:// loopback test
// origin, so a caller that forgets to wire a client cannot reach an internal
// target.
func TestFetch_ZeroClientUsesGuardedDefault(t *testing.T) {
	t.Parallel()
	_, key := testutil.NewSigningKey("k", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	origin := testutil.NewOrigin(testutil.MarshalManifest(
		testutil.Manifest(rampwellknown.RoleAgent, "agent.example", key),
	))
	defer origin.Close()

	_, err := rampwellknown.Fetch(context.Background(), origin.URL, rampwellknown.FetchOptions{})
	if !errors.Is(err, rampwellknown.ErrBlockedTarget) {
		t.Fatalf("want ErrBlockedTarget from the guarded default, got %v", err)
	}
}

func TestFetch_Errors(t *testing.T) {
	t.Parallel()
	_, key := testutil.NewSigningKey("k", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	brokerManifest := testutil.MarshalManifest(
		testutil.Manifest(rampwellknown.RoleBroker, "broker.example", key),
	)

	tests := []struct {
		name    string
		arrange func(o *testutil.Origin)
		expect  rampwellknown.Role
		wantErr error
	}{
		{
			name:    "404 yields ErrNoManifest",
			arrange: func(o *testutil.Origin) { o.SetManifestStatus(http.StatusNotFound) },
			wantErr: rampwellknown.ErrNoManifest,
		},
		{
			name:    "garbage body yields ErrSchemaInvalid",
			arrange: func(o *testutil.Origin) { o.SetManifest([]byte(`{"ver":"0.3"}`)) },
			wantErr: rampwellknown.ErrSchemaInvalid,
		},
		{
			name:    "role mismatch yields ErrRoleMismatch",
			arrange: func(_ *testutil.Origin) {},
			expect:  rampwellknown.RoleAgent,
			wantErr: rampwellknown.ErrRoleMismatch,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			origin := testutil.NewOrigin(brokerManifest)
			defer origin.Close()
			tc.arrange(origin)
			_, err := rampwellknown.Fetch(context.Background(), origin.URL, rampwellknown.FetchOptions{
				Client:     testutil.Client(),
				ExpectRole: tc.expect,
			})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("want %v, got %v", tc.wantErr, err)
			}
		})
	}
}
