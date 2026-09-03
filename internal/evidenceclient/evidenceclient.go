// Package evidenceclient reads one transaction's evidence row from the
// Exchange's admin plane.
//
// It is the consumer half of the contract evidenceview declares: that package
// owns the shape and the route, this one owns how the shape is fetched, checked
// and validated. Keeping the two apart lets evidenceview stay free of HTTP, so a
// service can import the shape without importing a client.
//
// It lives outside both service trees because the producer is the Exchange and
// the consumer is an operator CLI built from the Broker tree, and neither may
// import the other. That placement is also what makes the contract testable: a
// test standing beside the real handler can fetch through this client, so the
// wire format is proven by the code that ships rather than by a copy of it.
package evidenceclient

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceview"
)

// errorBodyLimit bounds how much of a failing response is quoted back to the
// operator. An admin plane behind a misconfigured tunnel can answer with a whole
// HTML error page, and printing all of it buries the status line.
const errorBodyLimit = 512

// Fetch reads the append-once row over the Exchange's admin plane. That plane is
// gated at the network layer only, so it is reached through a tunnel to the
// deployment rather than being exposed; the base URL comes from the operator.
//
// Validate runs here, at the decode boundary, so every caller downstream may
// dereference Evidence and TransactionState without a check of its own. A
// truncated or version-skewed payload is refused as an error rather than
// rendered as a chain with silently empty steps.
func Fetch(
	ctx context.Context, adminURL, txID string, timeout time.Duration,
) (*evidenceview.Response, error) {
	endpoint, err := EndpointURL(adminURL, txID)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("build evidence request for %s: %w", txID, err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := (&http.Client{Timeout: timeout}).Do(req)
	if err != nil {
		return nil, fmt.Errorf("read evidence for %s from %s: %w", txID, adminURL, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyLimit))
		return nil, fmt.Errorf("read evidence for %s from %s: %s: %s",
			txID, adminURL, resp.Status, strings.TrimSpace(string(body)))
	}

	var out evidenceview.Response
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return nil, fmt.Errorf("decode evidence for %s: %w", txID, err)
	}
	if err := out.Validate(); err != nil {
		return nil, fmt.Errorf("evidence for %s is incomplete: %w", txID, err)
	}
	return &out, nil
}

// EndpointURL appends the read path to the operator's base URL rather than
// replacing it, so an admin plane reached under a tunnel prefix still resolves.
//
// The scheme is checked because url.Parse accepts far more than a fetchable URL.
// "file:///etc/passwd" parses cleanly, and so does the common typo of omitting
// the scheme: "localhost:8091" parses as scheme "localhost" with an empty host.
// Both would otherwise reach the transport and fail there with a message about
// the wrong thing.
func EndpointURL(adminURL, txID string) (string, error) {
	base, err := url.Parse(adminURL)
	if err != nil {
		return "", fmt.Errorf("parse admin URL %q: %w", adminURL, err)
	}
	if base.Scheme != "http" && base.Scheme != "https" {
		return "", fmt.Errorf("admin URL %q must be http or https, got scheme %q", adminURL, base.Scheme)
	}
	if base.Host == "" {
		return "", fmt.Errorf("admin URL %q names no host", adminURL)
	}
	base.Path = strings.TrimSuffix(base.Path, "/") + evidenceview.Path
	base.RawQuery = url.Values{"tx": {txID}}.Encode()
	return base.String(), nil
}
