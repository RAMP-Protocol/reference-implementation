//go:build integration

package testutil

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// SendAbsoluteForm serializes a signed *http.Request to an HTTP/1.1 wire message
// whose request target is in ABSOLUTE FORM — the full scheme://host/path as the
// request-URI (RFC 7230 §5.3.2), the shape Go's net/http server parses into
// r.URL.Scheme and r.URL.Host. It dials socketHost directly and returns the
// response.
//
// A normal http.Client only ever emits origin-form (POST /path) to an origin
// server, so a raw socket write is the only way to exercise the absolute-form
// path — the vector by which a caller can populate r.URL.Scheme/Host without
// touching a header. Tests use this to prove a service sanitizes that vector
// before signature verification. req supplies the method, absolute URL, and
// (already-signed) headers; socketHost is the real listener address the
// connection dials and the Host header carries.
func SendAbsoluteForm(t *testing.T, socketHost string, req *http.Request, body []byte) *http.Response {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "%s %s HTTP/1.1\r\n", req.Method, req.URL.String())
	fmt.Fprintf(&b, "Host: %s\r\n", socketHost)
	for k, vs := range req.Header {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	fmt.Fprintf(&b, "Content-Length: %d\r\n\r\n", len(body))
	b.Write(body)

	conn, err := net.Dial("tcp", socketHost)
	if err != nil {
		t.Fatalf("dial %s: %v", socketHost, err)
	}
	defer conn.Close()
	if _, err := io.WriteString(conn, b.String()); err != nil {
		t.Fatalf("write raw request: %v", err)
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		t.Fatalf("read raw response: %v", err)
	}
	// Drain the body before the deferred conn.Close severs it: the lazily-read
	// body is bound to the socket, and callers read it after this function
	// returns — typically in a failure-diagnostic path, which must not print a
	// truncated body on the very regression it exists to explain.
	detached, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read raw response body: %v", err)
	}
	_ = resp.Body.Close()
	resp.Body = io.NopCloser(strings.NewReader(string(detached)))
	return resp
}
