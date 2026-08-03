package runhttp

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// trivialHandler is a no-op handler for the lifecycle tests: the servers exist to
// be started and shut down, not to serve traffic.
func trivialHandler() http.Handler {
	return http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
}

// TestServeGroup_CtxCancel_ShutsDownAndReturnsNil pins the co-managed shutdown
// invariant: cancelling the context gracefully stops every server and ServeGroup
// returns nil. Two loopback servers on OS-assigned ports (127.0.0.1:0).
func TestServeGroup_CtxCancel_ShutsDownAndReturnsNil(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1) // buffered: the goroutine must exit even if we time out
	go func() {
		done <- ServeGroup(
			ctx, testutil.DiscardLogger(),
			ServerSpec{Name: "a", Addr: "127.0.0.1:0", Handler: trivialHandler()},
			ServerSpec{Name: "b", Addr: "127.0.0.1:0", Handler: trivialHandler()},
		)
	}()

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("ServeGroup on ctx-cancel = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeGroup did not return within 5s of ctx cancel")
	}
}

// TestServeGroup_AddrInUse_ReturnsNamedErrorAndTearsDownSibling pins the
// fail-together invariant: a spec bound to an already-occupied address fails, its
// error (named by the spec) propagates as the group result, and the sibling server
// is torn down so ServeGroup returns promptly rather than hanging.
func TestServeGroup_AddrInUse_ReturnsNamedErrorAndTearsDownSibling(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupy addr: %v", err)
	}
	defer func() { _ = ln.Close() }()

	done := make(chan error, 1)
	go func() {
		// The errgroup self-cancels on the bind error, so a background context is enough.
		done <- ServeGroup(
			context.Background(), testutil.DiscardLogger(),
			ServerSpec{Name: "occupied", Addr: ln.Addr().String(), Handler: trivialHandler()},
			ServerSpec{Name: "sibling", Addr: "127.0.0.1:0", Handler: trivialHandler()},
		)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("ServeGroup on occupied addr = nil, want error")
		}
		// The spec Name is the stable contract; the OS bind-error wording is not.
		if !strings.Contains(err.Error(), "occupied") {
			t.Errorf("error %q does not name the failing spec %q", err, "occupied")
		}
		if errors.Is(err, http.ErrServerClosed) {
			t.Errorf("error is ErrServerClosed, want the real bind failure: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("ServeGroup did not return within 5s (sibling not torn down?)")
	}
}
