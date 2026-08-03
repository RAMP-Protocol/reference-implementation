//go:build integration && !zitadel

package transport_test

import (
	"context"
	"log/slog"
)

// maybeStartZitadel is a no-op when the `zitadel` build tag is absent: the fast
// integration tier fakes the upstream at the oidcup.Authenticator port and never
// stands up a real Zitadel. The real one is brought up by the same-named function
// in zitadel_on_test.go under `//go:build integration && zitadel`.
func maybeStartZitadel(context.Context, *slog.Logger) func() { return func() {} }
