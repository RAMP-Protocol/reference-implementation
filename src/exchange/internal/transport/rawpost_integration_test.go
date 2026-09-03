//go:build integration

package transport_test

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// The helpers in this file drive a mount with raw HTTP rather than a Connect
// client, for the tests that need the HTTP status itself. A Connect client maps
// the status to a code — and a gRPC client maps a 413 to CodeUnknown — which
// hides the very distinction the body-cap tests exist to make: whether an
// over-cap body was refused as a resource limit or as something else.

// rawReply is what a raw POST came back with, read in full and closed, so a
// test asserts on values rather than on a body still bound to a connection.
type rawReply struct {
	status int
	header http.Header
	body   string
}

// postRawConnect sends body straight at a Connect procedure over base, so the
// test controls the exact bytes on the wire. Whether the request is signed is
// base's business: the bare harness transport sends it unsigned, a signing
// transport signs it.
func postRawConnect(t *testing.T, base http.RoundTripper, url string, body []byte) rawReply {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build raw request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Connect-Protocol-Version", "1")
	resp, err := (&http.Client{Transport: base}).Do(req)
	if err != nil {
		t.Fatalf("raw post: %v", err)
	}
	defer resp.Body.Close()
	got, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read raw response: %v", err)
	}
	return rawReply{status: resp.StatusCode, header: resp.Header, body: string(got)}
}

// padJSON returns body with n spaces inserted before its closing brace. The
// result is the same JSON object — whitespace between tokens is not part of the
// message — so a request padded past a byte bound is still the same conformant
// message once parsed. That is what makes the persistence probe in a body-cap
// test load-bearing: with no bound, the padded request would be decoded,
// accepted and stored, and no wire rule would refuse it first.
func padJSON(body []byte, n int) []byte {
	if len(body) == 0 || body[len(body)-1] != '}' {
		panic(fmt.Sprintf("padJSON: %q is not a JSON object", body))
	}
	out := make([]byte, 0, len(body)+n)
	out = append(out, body[:len(body)-1]...)
	out = append(out, strings.Repeat(" ", n)...)
	return append(out, '}')
}

// assertRefusedTooLarge checks the three properties an over-cap refusal has on
// every mount: the 413 status, Connect's resource_exhausted code in the body,
// and the X-Request-ID the public surface stamps outermost — a refusal that
// cannot be correlated in the reject-path logs would regress the property the
// request-id ordering exists to give.
func assertRefusedTooLarge(t *testing.T, reply rawReply) {
	t.Helper()
	if reply.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("over-cap body: status = %d, want 413 — the raw-body bound did not bite (body %q)",
			reply.status, reply.body)
	}
	if !strings.Contains(reply.body, "resource_exhausted") {
		t.Errorf("over-cap body was not classified resource_exhausted: %s", reply.body)
	}
	if reply.header.Get(helpers.RequestIDHeader) == "" {
		t.Error("the refusal carries no X-Request-ID — the body bound was composed outside request-id")
	}
}

// assertReachedVerification checks that an UNSIGNED under-cap body got past the
// size gate and was refused by verification instead: a 401 carrying Connect's
// unauthenticated code. It proves the bound is not refusing everything, which
// the over-cap case alone cannot: an unsigned request is refused anyway, so a
// 413 by itself could come from a bound set to zero.
func assertReachedVerification(t *testing.T, reply rawReply) {
	t.Helper()
	if reply.status != http.StatusUnauthorized {
		t.Fatalf("under-cap unsigned body: status = %d, want 401 — it must reach verification, "+
			"not be refused by the size gate (body %q)", reply.status, reply.body)
	}
	if !strings.Contains(reply.body, "unauthenticated") {
		t.Errorf("an unsigned request was not refused by verification: %s", reply.body)
	}
}
