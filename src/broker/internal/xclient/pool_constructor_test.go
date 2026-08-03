package xclient

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// TestNewPoolRequiresHTTPClient pins that the exchange-client pool REJECTS a nil
// HTTP client at wiring time (panic-at-wire) instead of silently fabricating a
// fail-open &http.Client. The pool's client is the caller-influenced
// Broker→Exchange relay client the composition root injects; a nil client is a
// wiring bug and must fail loud rather than downgrade the relay to an unguarded
// default.
func TestNewPoolRequiresHTTPClient(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Fatal("NewPool(nil) must panic, but it returned normally")
		}
	}()
	_ = NewPool(nil)
}

// recordingTransport records the outbound requests routed through it, so a test
// can prove the pool actually issues its Broker→Exchange calls through the HTTP
// client it was constructed with. It short-circuits with an error — the URL it
// captured is the assertion, no live Exchange is needed.
type recordingTransport struct {
	got []string
}

func (t *recordingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	t.got = append(t.got, req.URL.String())
	return nil, errors.New("recorded")
}

// TestNewPoolUsesInjectedClient pins that the pool routes an outbound relay call
// through the HTTP client the composition root injected — the whole point of
// making the client a required constructor argument. A recording transport on
// the injected client observes the request; had the pool fabricated its own
// client the transport would never be reached and got would stay empty. This is
// the assertion the prior `p != nil`-only test lacked: it proves the injected
// client is on the outbound path, not merely retained.
func TestNewPoolUsesInjectedClient(t *testing.T) {
	rt := &recordingTransport{}
	p := NewPool(&http.Client{Transport: rt})

	// The call fails (the transport short-circuits) — irrelevant; the proof is
	// that the injected transport saw the request at all.
	_, _ = p.DiscoverResources(context.Background(), "https://exchange.example", &rampv1.ResourceQuery{})

	if len(rt.got) == 0 {
		t.Fatal("pool did not route the outbound request through the injected HTTP client")
	}
	if !strings.Contains(rt.got[0], "exchange.example") {
		t.Errorf("outbound request went to %q, want the injected endpoint host", rt.got[0])
	}
}
