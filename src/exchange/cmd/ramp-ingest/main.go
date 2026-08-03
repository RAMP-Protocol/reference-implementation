// Command ramp-ingest reads a RAMP JSON-L feed, maps every record to a
// proto-exact ramp.v1.ResourceEntry (terms[] that pass licenseterm.Validate),
// then signs and pushes them to the Exchange via the CatalogService.PushResources
// RPC — there is no direct-SQL path. The request is signed with a
// catalog-contributor Ed25519 key (RFC 9421) whose kid must be registered as an
// authorized contributor in the publisher's ramp.json.
//
// The push verdict (accepted / rejected / warnings) is reported to stderr. A
// non-zero rejected count is a build failure: the process exits non-zero so a
// partial catalog never passes silently.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/ingest"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "ramp-ingest: %v\n", err)
		os.Exit(1)
	}
}

// run parses flags, opens the feed, and drives the ingest pipeline. It is split
// from main so the deferred feed-close runs before the process exits (main only
// translates a non-nil error into a non-zero exit code).
func run(args []string) (err error) {
	fs := flag.NewFlagSet("ramp-ingest", flag.ContinueOnError)
	exchangeURL := fs.String("exchange-url", "", "Exchange base URL (required), e.g. http://exchange:8081")
	tenantID := fs.String("tenant", "", "tenant_id the entries are pushed under (required)")
	// --key has NO default: there is no committed contributor key to fall back
	// to. An operator must supply an explicitly-generated keypair path or
	// the ingester refuses to run. Generate one with scripts/gen-demo-agent-key.sh
	// (or the contributor-key scheme) and pass its path here.
	keyPath := fs.String(
		"key",
		"",
		"path to the catalog-contributor Ed25519 keypair JSON (required; no default)",
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *exchangeURL == "" {
		return errors.New("--exchange-url is required")
	}
	if *tenantID == "" {
		return errors.New("--tenant is required")
	}
	if *keyPath == "" {
		return errors.New("--key is required: supply an explicitly-generated " +
			"Ed25519 contributor keypair path (no committed default exists)")
	}

	feed := io.Reader(os.Stdin)
	if rest := fs.Args(); len(rest) > 0 {
		f, openErr := os.Open(rest[0]) //nolint:gosec // operator-supplied feed path
		if openErr != nil {
			return fmt.Errorf("open feed: %w", openErr)
		}
		defer func() {
			if cerr := f.Close(); cerr != nil && err == nil {
				err = cerr
			}
		}()
		feed = f
	}

	_, err = ingest.Run(context.Background(), ingest.Options{
		ExchangeURL: *exchangeURL,
		TenantID:    *tenantID,
		KeyPath:     *keyPath,
		Feed:        feed,
		Report:      os.Stderr,
		Clk:         clock.System{},
	})
	return err
}
