package registry_test

// Constructor guards for the health refresher.
//
// Both arguments under test here are outbound trust boundaries, not
// conveniences. The probe client dials an address the exchange advertises about
// ITSELF and the pass writes that address into the column the relay's allowlist
// compares a caller-supplied endpoint against, so a fabricated default would be
// an unguarded client on the broker's SSRF boundary. The resolver decides WHICH
// address gets dialled. A nil for either is a wiring bug, and the composition
// root launches the refresher in its own goroutine where nothing recovers -- so
// a nil that is tolerated at construction becomes a process exit at the first
// probe instead of a build failure at start-up.
//
// The exchange client pool pins the same contract for the same reason.

import (
	"context"
	"net/http"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/registry"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// stubHealthRepo satisfies repo.ExchangeHealthRepo. The constructor never calls
// it, so the methods only need to exist.
type stubHealthRepo struct{}

func (stubHealthRepo) ListUnblocked(context.Context) ([]repo.Exchange, error) { return nil, nil }

func (stubHealthRepo) SetProbeResult(context.Context, string, string, bool) error { return nil }

// stubResolver satisfies registry.EndpointResolver.
type stubResolver struct{}

func (stubResolver) ResolveEndpoint(context.Context, string) (string, error) { return "", nil }

func TestNewRefresherRequiresHTTPClient(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewRefresher with a nil HTTP client must panic, but it returned normally")
		}
	}()
	_ = registry.NewRefresher(stubHealthRepo{}, stubResolver{}, nil, testutil.DiscardLogger(), 0)
}

func TestNewRefresherRequiresEndpointResolver(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewRefresher with a nil endpoint resolver must panic, but it returned normally")
		}
	}()
	_ = registry.NewRefresher(stubHealthRepo{}, nil, http.DefaultClient, testutil.DiscardLogger(), 0)
}
