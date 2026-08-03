package ingest

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampauth"
)

// signatureTTL bounds the RFC 9421 signature's validity window. The push is a
// single synchronous RPC, so a short window suffices; it matches the e2e
// harness's 30s TTL (tests/e2e/harness/catalog_push.py).
const signatureTTL = 30 * time.Second

// ContributorKey is the on-disk shape of a catalog-contributor Ed25519 keypair,
// matching scripts/gen-demo-agent-key.sh and the e2e harness fixture: a kid plus
// base64url-encoded raw (32-byte) seed and public key.
type ContributorKey struct {
	KID        string `json:"kid"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
}

// LoadContributorKey reads and decodes the contributor keypair at path. The
// kid becomes the PushResources caller_id (Gate 1 keyID and Gate 2 contributor
// identity must both resolve to it).
func LoadContributorKey(path string) (kid string, priv ed25519.PrivateKey, err error) {
	raw, err := os.ReadFile(path) //nolint:gosec // operator-supplied key path
	if err != nil {
		return "", nil, fmt.Errorf("read contributor key %q: %w", path, err)
	}
	var doc ContributorKey
	if err := json.Unmarshal(raw, &doc); err != nil {
		return "", nil, fmt.Errorf("parse contributor key %q: %w", path, err)
	}
	if doc.KID == "" {
		return "", nil, fmt.Errorf("contributor key %q: missing kid", path)
	}
	seed, err := base64.RawURLEncoding.DecodeString(doc.PrivateKey)
	if err != nil {
		return "", nil, fmt.Errorf("contributor key %q: decode private_key: %w", path, err)
	}
	if len(seed) != ed25519.SeedSize {
		return "", nil, fmt.Errorf(
			"contributor key %q: private_key is %d bytes, want %d (raw seed)",
			path, len(seed), ed25519.SeedSize,
		)
	}
	return doc.KID, ed25519.NewKeyFromSeed(seed), nil
}

// NewSigningClient builds the signed *http.Client the catalog push speaks
// through: the SDK signing RoundTripper over http.DefaultTransport, gated to
// /ramp.* procedures, publishing kid as the covered Signature-Agent directory
// origin, with a MonotonicWindow so batch pushes within the same wall-clock
// second never collide in the Exchange's replay store. The RFC 9421 keyid is
// the RFC 7638 thumbprint of priv's public key. Construction lives at the
// pipeline root so the private key never travels through PushEntries.
func NewSigningClient(kid string, priv ed25519.PrivateKey, clk clock.Clock) (*http.Client, error) {
	if clk == nil {
		clk = clock.System{}
	}
	keyID, err := helpers.Thumbprint(priv.Public().(ed25519.PublicKey))
	if err != nil {
		return nil, fmt.Errorf("derive contributor keyid thumbprint: %w", err)
	}
	signer, err := helpers.NewEd25519Signer(keyID, priv)
	if err != nil {
		return nil, fmt.Errorf("build contributor signer: %w", err)
	}
	rt := core.NewSigningTransport(signer, http.DefaultTransport,
		core.WithSignPredicate(rampauth.IsRAMPProcedure),
		core.WithSignatureAgent(kid),
		core.WithWindow(core.MonotonicWindow(clk.Now, signatureTTL)),
	)
	return &http.Client{Transport: rt}, nil
}

// PushReport is the structured verdict of a PushResources call: the accepted /
// rejected counts the Exchange returned plus any non-fatal warnings (unknown
// vocab tokens, OTHER obligations without detail). A non-zero Rejected count is
// a build-level failure the caller surfaces as a non-zero exit.
type PushReport struct {
	Accepted int32
	Rejected int32
	Warnings []string
}

// HasRejections reports whether any entry was rejected.
func (r PushReport) HasRejections() bool { return r.Rejected > 0 }

// PushEntries sends a single PushResourcesRequest covering entries to the
// Exchange's CatalogService.PushResources over Connect, and returns the
// structured verdict. callerID is the contributor key's kid (Gate 1 + Gate 2
// identity — the contributor DOMAIN, which the signed transport also publishes
// as its Signature-Agent directory origin). client is the pre-wired signed
// HTTP client (NewSigningClient) — the private key stays at the pipeline root.
// It is RPC-only — there is no SQL path.
//
// The direct NewCatalogServiceClient + signing-transport composition is the
// canonical pattern for single-caller publisher tooling: CatalogService is
// publisher-facing with exactly one caller, so an SDK CatalogClient wrapper
// would be premature abstraction — add one only when a second caller appears.
func PushEntries(
	ctx context.Context,
	exchangeURL, tenantID, callerID string,
	client *http.Client,
	entries []*rampv1.ResourceEntry,
) (PushReport, error) {
	svc := rampconnect.NewCatalogServiceClient(
		client,
		strings.TrimRight(exchangeURL, "/"),
		connect.WithGRPC(),
	)
	resp, err := svc.PushResources(ctx, connect.NewRequest(&rampv1.PushResourcesRequest{
		TenantId: tenantID,
		CallerId: callerID,
		Entries:  entries,
	}))
	if err != nil {
		return PushReport{}, fmt.Errorf("push resources: %w", err)
	}
	return PushReport{
		Accepted: resp.Msg.GetAccepted(),
		Rejected: resp.Msg.GetRejected(),
		Warnings: resp.Msg.GetWarnings(),
	}, nil
}

// WriteReport prints a structured, human-readable verdict to w. Write errors on
// the report sink (stderr) are non-fatal and intentionally ignored — the
// authoritative outcome is the returned PushReport / process exit code.
func WriteReport(w io.Writer, r PushReport) {
	_, _ = fmt.Fprintf(w, "push: accepted=%d rejected=%d warnings=%d\n", r.Accepted, r.Rejected, len(r.Warnings))
	for _, warn := range r.Warnings {
		_, _ = fmt.Fprintf(w, "  warning: %s\n", warn)
	}
	if r.HasRejections() {
		_, _ = fmt.Fprintf(w, "  ERROR: %d entr(y/ies) rejected — catalog push incomplete\n", r.Rejected)
	}
}

// Options configures a full ingest Run.
type Options struct {
	// ExchangeURL is the Exchange base URL (required).
	ExchangeURL string
	// TenantID is the tenant the entries are pushed under (required).
	TenantID string
	// KeyPath is the catalog-contributor Ed25519 keypair JSON path (required).
	KeyPath string
	// Feed is the JSON-L source to parse.
	Feed io.Reader
	// Report sink for the structured verdict; nil discards it.
	Report io.Writer
	// Clk supplies the wall clock for RFC 9421 created/expires; nil → System.
	Clk clock.Clock
}

// Run executes the full ingest pipeline (parse → map → sign+push) and returns a
// non-nil error when configuration is incomplete, the feed is malformed, the
// push transport fails, or any entry was rejected. main is a thin wrapper over
// this so the parse/map/push/exit-code contract is exercised by tests.
func Run(ctx context.Context, opts Options) (PushReport, error) {
	if opts.ExchangeURL == "" {
		return PushReport{}, fmt.Errorf("exchange URL is required")
	}
	if opts.TenantID == "" {
		return PushReport{}, fmt.Errorf("tenant is required")
	}

	records, err := ParseJSONL(opts.Feed)
	if err != nil {
		return PushReport{}, err
	}
	entries, err := MapRecords(records)
	if err != nil {
		return PushReport{}, err
	}

	kid, priv, err := LoadContributorKey(opts.KeyPath)
	if err != nil {
		return PushReport{}, err
	}
	client, err := NewSigningClient(kid, priv, opts.Clk)
	if err != nil {
		return PushReport{}, err
	}

	report, err := PushEntries(ctx, opts.ExchangeURL, opts.TenantID, kid, client, entries)
	if err != nil {
		return PushReport{}, err
	}
	if opts.Report != nil {
		WriteReport(opts.Report, report)
	}
	if report.HasRejections() {
		return report, fmt.Errorf("%d of %d entries rejected", report.Rejected, len(entries))
	}
	return report, nil
}

// MapRecords maps every parsed record to a proto-exact ResourceEntry, wrapping
// the first mapping failure with the offending record's index and URI.
func MapRecords(records []Record) ([]*rampv1.ResourceEntry, error) {
	entries := make([]*rampv1.ResourceEntry, 0, len(records))
	for i := range records {
		entry, err := mapRecord(records[i])
		if err != nil {
			return nil, fmt.Errorf("record %d (%s%s): %w", i, records[i].Domain, records[i].Path, err)
		}
		entries = append(entries, entry)
	}
	return entries, nil
}
