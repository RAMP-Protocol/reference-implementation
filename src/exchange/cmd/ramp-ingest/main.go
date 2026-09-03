// Command ramp-ingest reads a RAMP JSON-L feed, maps every record to a
// proto-exact ramp.v1.ResourceEntry with its restriction tokens canonicalised,
// then signs and pushes them to the Exchange through the protocol SDK's
// catalog client, over the CatalogService.PushResources RPC — there is no
// direct-SQL path. Every request is signed with a catalog-contributor Ed25519
// key (RFC 9421) whose kid must be registered as an authorized contributor in
// the publisher's ramp.json.
//
// A feed larger than the wire bound on one submission is pushed as several
// submissions in feed order, each stored or refused whole. The verdict — the
// accepted count, the warnings, and per submission what was stored, refused
// or not sent — is reported to stderr. The exit status is the whole pass/fail
// signal: the process exits non-zero on the first submission that did not
// store, so a partial catalog never passes silently, and re-running the same
// feed converges.
//
// Not every stopped run is a refusal, and the report says which it was. A
// submission the Exchange refused is printed REFUSED and stored nothing. One
// that got no answer at all — a deadline, a dropped connection — is printed
// NOT CONFIRMED, because the Exchange may have committed it after the client
// stopped listening. Both exit non-zero; only the second may already be stored.
//
// With --check the feed is only parsed, mapped and validated locally with the
// SDK's entry validation — no key, no Exchange, no tenant — and the process
// exits non-zero when any entry carries a violation, listing every finding
// with its rule id and field path.
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
	if err := run(os.Args[1:], os.Stderr); err != nil {
		fmt.Fprintf(os.Stderr, "ramp-ingest: %v\n", err)
		os.Exit(1)
	}
}

// run parses flags, opens the feed, and drives the ingest pipeline — or, under
// --check, the local feed check — writing the verdict to report. It is split
// from main so the deferred feed-close runs before the process exits (main
// only translates a non-nil error into a non-zero exit code).
func run(args []string, report io.Writer) (err error) {
	fs := flag.NewFlagSet("ramp-ingest", flag.ContinueOnError)
	check := fs.Bool(
		"check",
		false,
		"validate the feed locally and exit non-zero on any violation: parse, map and run the SDK's "+
			"entry validation; needs no --key, --exchange-url or --tenant, and never dials",
	)
	exchangeURL := fs.String("exchange-url", "", "Exchange base URL (required), e.g. http://exchange:8081")
	// The recipient the push is addressed to. It defaults to the host of
	// --exchange-url, because an Exchange is reached at its own identity and a
	// second flag for the same fact could only ever disagree with the first.
	//
	// The override exists for a routing shim in front of the Exchange — a test
	// harness reaching it through a mapped 127.0.0.1 port, where the dialled
	// host names no Exchange at all. Outside that, leave it unset.
	exchangeDomain := fs.String(
		"exchange",
		"",
		"recipient Exchange's bare domain; defaults to the host of --exchange-url, "+
			"override only when dialling through a port mapping",
	)
	tenantID := fs.String("tenant", "", "tenant_id the entries are pushed under (required)")
	// --key has NO default: there is no committed contributor key to fall back
	// to. An operator must supply an explicitly-generated keypair path or
	// the ingester refuses to run. Mint one with
	// scripts/gen-contributor-key.sh <contributor-id> and pass its path here.
	keyPath := fs.String(
		"key",
		"",
		"path to the catalog-contributor Ed25519 keypair JSON (required; no default)",
	)
	if err := fs.Parse(args); err != nil {
		return err
	}
	// The connection flags are checked before the feed is opened, so a
	// missing flag is reported as such and never as a feed error. --check
	// needs none of them: it has no Exchange to reach and no key to sign with.
	if !*check {
		if err := requireConnectionFlags(*exchangeURL, *tenantID, *keyPath); err != nil {
			return err
		}
	}

	feed, closeFeed, err := openFeed(fs.Args())
	if err != nil {
		return err
	}
	defer func() {
		if cerr := closeFeed(); cerr != nil && err == nil {
			err = cerr
		}
	}()

	if *check {
		return runCheck(feed, report)
	}
	_, err = ingest.Run(context.Background(), ingest.Options{
		ExchangeURL: *exchangeURL,
		Exchange:    *exchangeDomain,
		TenantID:    *tenantID,
		KeyPath:     *keyPath,
		Feed:        feed,
		Report:      report,
		Clk:         clock.System{},
	})
	return err
}

// requireConnectionFlags refuses a push run that lacks any of the three flags a
// push cannot do without, naming the missing one.
func requireConnectionFlags(exchangeURL, tenantID, keyPath string) error {
	if exchangeURL == "" {
		return errors.New("--exchange-url is required")
	}
	if tenantID == "" {
		return errors.New("--tenant is required")
	}
	if keyPath == "" {
		return errors.New("--key is required: supply an explicitly-generated " +
			"Ed25519 contributor keypair path (no committed default exists)")
	}
	return nil
}

// openFeed returns the feed to read — the first positional argument as a file,
// or standard input when there is none — and the close to run when done.
func openFeed(positional []string) (feed io.Reader, closeFeed func() error, err error) {
	if len(positional) == 0 {
		return os.Stdin, func() error { return nil }, nil
	}
	f, err := os.Open(positional[0]) //nolint:gosec // operator-supplied feed path
	if err != nil {
		return nil, nil, fmt.Errorf("open feed: %w", err)
	}
	return f, f.Close, nil
}

// runCheck drives the local feed check and turns a feed with any violation
// into a non-nil error, so main exits non-zero on it. The findings are written
// to report before the verdict, so a refused feed lists every reason.
func runCheck(feed io.Reader, report io.Writer) error {
	result, err := ingest.Check(feed)
	if err != nil {
		return err
	}
	ingest.WriteCheckReport(report, result)
	if !result.OK() {
		return fmt.Errorf("check: %d violation(s) across %d record(s); the Exchange would refuse the push",
			result.Violations(), result.Records)
	}
	return nil
}
