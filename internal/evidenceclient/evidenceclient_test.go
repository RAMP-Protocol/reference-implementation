package evidenceclient_test

import (
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceclient"
)

// The expected URLs below are LITERALS on purpose. They are the wire contract
// between the operator's -admin-url and the route the Exchange mounts, so a test
// that rebuilt them from the same constants the code uses would follow any
// change instead of catching it.

// EndpointURL is the only thing standing between the operator's -admin-url and
// the request, and a wrong join produces a 404 that reads like a missing
// transaction rather than a malformed URL. The base is appended to, never
// replaced, so an admin plane reached under a tunnel prefix still resolves.
func TestEvidenceURL_appendsTheReadPathToTheOperatorsBase(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		base string
		want string
	}{
		{
			name: "loopback tunnel, the usual case",
			base: "http://127.0.0.1:8091",
			want: "http://127.0.0.1:8091/ops/transaction-evidence?tx=tx-1",
		},
		{
			name: "trailing slash does not double up",
			base: "http://127.0.0.1:8091/",
			want: "http://127.0.0.1:8091/ops/transaction-evidence?tx=tx-1",
		},
		{
			name: "a tunnel prefix is kept, not replaced",
			base: "https://ops.example/exchange",
			want: "https://ops.example/exchange/ops/transaction-evidence?tx=tx-1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := evidenceclient.EndpointURL(tc.base, "tx-1")
			if err != nil {
				t.Fatalf("EndpointURL(%q): %v", tc.base, err)
			}
			if got != tc.want {
				t.Errorf("EndpointURL(%q) = %q, want %q", tc.base, got, tc.want)
			}
		})
	}
}

// A transaction id carrying a URL metacharacter must land in the query as one
// value, not as a second parameter the handler would read separately.
func TestEvidenceURL_escapesTheTransactionID(t *testing.T) {
	t.Parallel()
	got, err := evidenceclient.EndpointURL("http://127.0.0.1:8091", "tx&admin=1")
	if err != nil {
		t.Fatalf("EndpointURL: %v", err)
	}
	if !strings.HasSuffix(got, "?tx=tx%26admin%3D1") {
		t.Errorf("transaction id was not escaped into a single value: %q", got)
	}
}

// url.Parse accepts anything with a colon in it, so an unusable base reaches
// the transport and fails there with a message about the wrong thing. These two
// are refused where the operator can still read what they typed.
func TestEvidenceURL_refusesABaseThatCannotBeFetched(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		base string
		want string
	}{
		// The common typo: omitting the scheme makes url.Parse read the host
		// as one, so "localhost:8091" arrives with scheme "localhost".
		{name: "host and port with no scheme", base: "localhost:8091", want: "must be http or https"},
		{name: "a scheme that is not HTTP", base: "file:///etc/passwd", want: "must be http or https"},
		{name: "no host at all", base: "http:///ops", want: "names no host"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := evidenceclient.EndpointURL(tc.base, "tx-1")
			if err == nil {
				t.Fatalf("EndpointURL(%q) accepted an unusable base and returned %q", tc.base, got)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %q should say %q", err, tc.want)
			}
		})
	}
}
