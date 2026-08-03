package transport_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestExchangeFault_SingleGenericEnvelopeSource is the structural red guard for
// the generic (no-reason) ExchangeService ErrorDetail envelope having exactly
// ONE source of truth.
//
// WHY A STRUCTURAL GUARD (not a behavioral one). The fix under test rewrites
// reportUsageError to delegate to genericFaultError, producing a byte-identical
// envelope (Domain=ramp.v1.ExchangeService + non-authoritative Message + any
// exchange.Error field metadata, no typed reason oneof). The change is
// behavior-preserving: the ReportUsage and DiscoverResources fault envelopes are
// identical BEFORE and AFTER the refactor. A behavioral assertion "ReportUsage
// envelope == generic envelope" is therefore GREEN today and cannot serve as a
// TDD-red artifact — the two bodies are already byte-identical. The behavior is
// genuinely unobservable-to-change, so per the write-test structural-disease
// exception the red artifact is the source-level guard that the later
// sweep-verify re-runs, mirroring the disease-scan command
//
//	grep -rn 'connectserver.AttachErrorDetail(' src/ internal/ --include='*.go' | grep -v _test.go
//
// The disease: two public fault wrappers (genericFaultError, reportUsageError)
// build the generic envelope with byte-identical connectserver.AttachErrorDetail
// bodies under different names — two sources that can drift when the envelope
// changes (a new metadata key, a per-RPC domain). Today jscpd misses it only
// because the surrounding docstrings differ in length, defeating textual clone
// detection.
//
// The behavioral regression guard stays elsewhere and MUST stay green across the
// refactor: the 11 assertReportRejectionField assertions in
// report_usage_integration_test.go pin the ReportUsage envelope (Domain +
// metadata[field]) and assertErrorDomain in exchange_negatives_integration_test.go
// pins the generic DiscoverResources envelope, both through the real Connect RPC
// surface.
//
// The invariant this guard pins: connectserver.AttachErrorDetail — the shared SDK
// call that constructs the generic no-reason envelope — appears exactly ONCE in
// the exchange transport package's non-test source (only in genericFaultError).
// executeTxError uses the distinct typed-reason connectserver.AttachDetail path,
// so it is not counted. Both sanctioned fixes satisfy this: delegating
// reportUsageError to genericFaultError, or deleting reportUsageError and routing
// the handler through genericFaultError. It FAILS today (two call sites) and
// passes once the duplicate body is collapsed.
func TestExchangeFault_SingleGenericEnvelopeSource(t *testing.T) {
	t.Parallel()

	const marker = "connectserver.AttachErrorDetail("

	// go test runs with cwd = package directory, so the package's own source
	// files are the non-test *.go files here. Scanning source text (not runtime
	// behavior) is the sanctioned shape ONLY because this is a behavior-preserving
	// dedup with no observable-to-change envelope.
	goFiles, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("glob package sources: %v", err)
	}

	var sites []string
	for _, f := range goFiles {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		src, readErr := os.ReadFile(f)
		if readErr != nil {
			t.Fatalf("read %s: %v", f, readErr)
		}
		lines := strings.Split(string(src), "\n")
		for i, line := range lines {
			if strings.Contains(line, marker) {
				sites = append(sites, filepath.Base(f)+":"+itoa(i+1))
			}
		}
	}

	if len(sites) != 1 {
		t.Fatalf("generic ExchangeService fault envelope has %d source(s) via %q, want exactly 1 "+
			"(genericFaultError is the single source of truth; reportUsageError must delegate, "+
			"not duplicate the AttachErrorDetail body). Call sites: %v",
			len(sites), marker, sites)
	}
}

// itoa avoids a strconv import for the single line-number rendering above.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}
