//go:build integration

package transport_test

import (
	"log/slog"
	"net/http"
	"net/url"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// The evidence route's failure line must carry request_id.
//
// An operator reading this plane during a dispute has a request id and a
// transaction id. A failure line that carries only the transaction id cannot be
// joined to the request that produced it, so a 500 seen by the caller and a 500
// recorded by the server cannot be shown to be the same event.
//
// The FAILURE is driven for real: closing the pool makes the repository's query
// fail, the service wraps it as an internal error, and the handler takes the 500
// branch. Nothing is mocked and nothing reaches past a layer — the request goes
// over real HTTP through the same WrapAdminSurface the server builds, and the
// observation is the surface's own slog output, which Testing Doctrine point 9
// permits as an observation seam.
//
// This is the handler's ONLY logging site. It used to have a second, for a
// failed response write, which was removed rather than left untested: that error
// reports only a synchronous write failure, so it stayed silent for most of the
// disconnects it was meant to record, and the caller sees the real symptom as a
// decode failure over a truncated body regardless.
func TestTransactionEvidence_ReadFailureLineCarriesRequestID(t *testing.T) {
	const reqID = "corr-evidence-read-failure"

	h := newTestHarness(t)
	buf := &safeBuffer{}
	_, baseURL := startAdminServerWithLogger(t, h, "127.0.0.0/8",
		slog.New(slog.NewJSONHandler(buf, nil)))

	// Break the backend the read depends on. Closing the pool is the whole
	// arrangement: the next query returns an error that is not "no rows", which
	// is what separates the 500 branch from the 404 one.
	h.pool.Close()

	// A well-formed transaction id, so the request passes the shape check and
	// reaches the service. Which id it is does not matter — the query fails
	// before it can match or miss.
	target := baseURL + transport.TransactionEvidencePath +
		"?tx=" + url.QueryEscape("00000000-0000-4000-8000-000000000000")
	req, err := http.NewRequestWithContext(h.ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("X-Request-ID", reqID)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", target, err)
	}
	defer func() { _ = resp.Body.Close() }()

	// The caller's half of the event.
	if resp.StatusCode != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", resp.StatusCode)
	}

	// The server's half, and the id that joins them.
	line := findLogLine(t, buf.String(), "transaction evidence read failed")
	if got := line["request_id"]; got != reqID {
		t.Fatalf("read-failure line request_id = %v, want %q\nfull log:\n%s",
			got, reqID, buf.String())
	}
	// The transaction id stays on the line too: request_id joins the line to the
	// request, transaction_id names the row that could not be read. Neither
	// replaces the other.
	if line["transaction_id"] == nil {
		t.Errorf("read-failure line lost transaction_id\nfull log:\n%s", buf.String())
	}
	// The error itself must reach the line. Without it the record says a read
	// failed and never says why.
	if line["err"] == nil {
		t.Errorf("read-failure line carries no err attribute\nfull log:\n%s", buf.String())
	}
}
