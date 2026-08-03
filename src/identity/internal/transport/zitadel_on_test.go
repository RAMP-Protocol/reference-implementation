//go:build integration && zitadel

package transport_test

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oidcup"
)

// zitadelRedirectURI is the identity service's own /callback as registered in
// Zitadel by the test bootstrap. It only needs to MATCH a registered URI — the
// headless-login helper intercepts Zitadel's 302 to it, so the identity server's
// actual (random) httptest port is irrelevant to Zitadel and need not be fixed.
const zitadelRedirectURI = "http://127.0.0.1:53217/callback"

var sharedZitadel *testutil.SharedZitadel

// maybeStartZitadel brings up the shared real Zitadel for the `zitadel` tier,
// once per package. On failure (Docker unavailable, image pull failure, or host
// port 8080 busy) it logs and leaves sharedZitadel nil so the tier's tests skip
// rather than fail the whole package.
func maybeStartZitadel(ctx context.Context, logger *slog.Logger) func() {
	z, cleanup, err := testutil.StartSharedZitadel(ctx, logger)
	if err != nil {
		// Diagnostic: TestMain hands us a discard logger, so this failure was
		// invisible in CI and the real-Zitadel tests only reported the generic
		// "unavailable". Print the actual error to stderr so the job trace shows
		// WHY Zitadel did not come up (e.g. a port-wait timeout under dind).
		fmt.Fprintf(os.Stderr, "StartSharedZitadel failed: %v\n", err)
		logger.Warn("start shared zitadel; real-zitadel tests will skip", "err", err)
		return func() {}
	}
	sharedZitadel = z
	return cleanup
}

func requireZitadel(t *testing.T) *testutil.SharedZitadel {
	t.Helper()
	if sharedZitadel == nil {
		// The real-Zitadel tier runs unconditionally: selecting the `zitadel`
		// build tag is an explicit request to exercise the real upstream, so a
		// Zitadel that will not boot (Docker down, image unpullable, or host port
		// 8080 busy) is a failure, never a silent skip.
		t.Fatal("shared Zitadel unavailable (Docker down, image unpullable, or host port 8080 busy)")
	}
	return sharedZitadel
}

// newZitadelFixture wires the auth-server fixture with the REAL oidcup.Zitadel
// upstream (real go-oidc discovery + JWKS ID-token verification) and a headless
// login against the shared Zitadel as the drive func.
func newZitadelFixture(t *testing.T) *authFixture {
	t.Helper()
	z := requireZitadel(t)
	ctx := t.Context()
	up, err := oidcup.New(ctx, oidcup.Config{
		Issuer: z.Issuer, ClientID: z.ClientID, ClientSecret: z.ClientSecret,
		RedirectURL: zitadelRedirectURI,
	})
	if err != nil {
		t.Fatalf("oidcup.New against real Zitadel: %v", err)
	}
	user, password := testutil.AliceLogin()
	drive := func(t *testing.T, authorizeLoc string) (string, string) {
		code, state, lerr := testutil.HeadlessLogin(ctx, z.Issuer, authorizeLoc, zitadelRedirectURI, user, password)
		if lerr != nil {
			t.Fatalf("headless Zitadel login: %v", lerr)
		}
		return code, state
	}
	return buildAuthFixture(t, up, drive, authServerOpts{})
}
