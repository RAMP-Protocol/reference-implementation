package rampwellknown

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"
)

const (
	maxDocBytes    = 64 * 1024
	defaultTimeout = 5 * time.Second
)

// HTTPDoer is the minimal contract the library needs from an *http.Client.
// Tests substitute a rewriting client that routes to a local httptest server.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// FetchOptions tunes a manifest fetch. Zero values get safe defaults.
type FetchOptions struct {
	// Client performs the GET. It is REQUIRED: the SSRF guard is SDK-owned, so a
	// caller constructs the client once from the SDK factory
	// (resolvers.NewGuardedClientFromEnv) at its composition root and injects it
	// here. A nil Client is a fail-loud ErrNoClient — this package never wraps or
	// re-exports the SDK guarded-client factory as an in-package default.
	Client HTTPDoer
	// Scheme overrides the URL scheme for bare hosts; default "https".
	Scheme string
	// Port, when set, is appended to a bare host (local/compose stacks).
	Port string
	// Timeout bounds a single fetch; default 5s.
	Timeout time.Duration
	// ExpectRole, when not RoleUnspecified, makes Fetch reject a manifest
	// whose role differs (ErrRoleMismatch).
	ExpectRole Role
}

func (o FetchOptions) client() (HTTPDoer, error) {
	if o.Client == nil {
		return nil, ErrNoClient
	}
	return o.Client, nil
}

func (o FetchOptions) timeout() time.Duration {
	if o.Timeout > 0 {
		return o.Timeout
	}
	return defaultTimeout
}

// Fetch GETs host's /.well-known/ramp.json, schema-validates it, decodes it via
// protojson, and (optionally) asserts its role. A 404 yields ErrNoManifest; a
// transient/non-2xx failure yields ErrFetch; a malformed body yields
// ErrSchemaInvalid; a role mismatch yields ErrRoleMismatch.
func Fetch(ctx context.Context, host string, opts FetchOptions) (*Manifest, error) {
	u, err := ManifestURL(host, opts.Scheme, opts.Port)
	if err != nil {
		return nil, err
	}
	client, err := opts.client()
	if err != nil {
		return nil, err
	}
	raw, err := getDoc(ctx, client, u, opts.timeout())
	if err != nil {
		return nil, err
	}
	return ParseManifest(raw, opts.ExpectRole)
}

// ParseManifest schema-validates raw, decodes it via protojson, and asserts
// role when expect is not RoleUnspecified. Exported so producers and tests can
// round-trip bytes without an HTTP round-trip.
func ParseManifest(raw []byte, expect Role) (*Manifest, error) {
	var m Manifest
	if err := decodeValidated(raw, &m, ValidateManifest); err != nil {
		return nil, err
	}
	if expect != RoleUnspecified && m.GetRole() != expect {
		return nil, fmt.Errorf("%w: want %s got %s", ErrRoleMismatch, expect, m.GetRole())
	}
	return &m, nil
}

// FetchWBA GETs host's /.well-known/http-message-signatures-directory, schema-
// validates it, and decodes it via protojson into a WBAFile. A 404 yields
// ErrNoManifest; a transient/non-2xx failure yields ErrFetch; a malformed body
// yields ErrSchemaInvalid. FetchOptions.ExpectRole is not consulted — the WBA
// directory carries no role.
func FetchWBA(ctx context.Context, host string, opts FetchOptions) (*WBAFile, error) {
	u, err := WBAURL(host, opts.Scheme, opts.Port)
	if err != nil {
		return nil, err
	}
	client, err := opts.client()
	if err != nil {
		return nil, err
	}
	raw, err := getDoc(ctx, client, u, opts.timeout())
	if err != nil {
		return nil, err
	}
	return ParseWBA(raw)
}

// ParseWBA schema-validates raw and decodes it via protojson into a WBAFile.
// Exported so producers and tests can round-trip bytes without an HTTP call.
func ParseWBA(raw []byte) (*WBAFile, error) {
	var f WBAFile
	if err := decodeValidated(raw, &f, ValidateWBA); err != nil {
		return nil, err
	}
	return &f, nil
}

// getDoc performs the GET and returns the (size-bounded) body. 404 →
// ErrNoManifest; any other non-2xx or transport/read error → ErrFetch.
func getDoc(ctx context.Context, client HTTPDoer, rawURL string, timeout time.Duration) ([]byte, error) {
	status, _, body, err := httpGet(ctx, client, rawURL, timeout)
	if err != nil {
		return nil, err
	}
	if status == http.StatusNotFound {
		return nil, ErrNoManifest
	}
	if status < 200 || status >= 300 {
		return nil, fmt.Errorf("%w: %s: status %d", ErrFetch, rawURL, status)
	}
	return body, nil
}

// httpGet issues the GET and fully reads the size-bounded body under a single
// timeout boundary, returning the raw status, headers, and body. Transport or
// read failures return ErrFetch; HTTP status is left for the caller to branch
// on (getDoc maps 404/non-2xx; the Cache also reads Cache-Control from header).
func httpGet(
	ctx context.Context, client HTTPDoer, rawURL string, timeout time.Duration,
) (int, http.Header, []byte, error) {
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// rawURL's host can be REQUEST-DERIVED on the discovery path: after the WBA
	// split it is built from the caller-supplied Signature-Agent directory. SSRF
	// is therefore mitigated by the SDK-guarded HTTP client the discovery callers
	// inject (constructed once from resolvers.NewGuardedClientFromEnv at the
	// composition root); callers on request-influenced hosts MUST pass a guarded
	// client, never a fail-open http.DefaultClient.
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, rawURL, nil) //nolint:noctx // ctx carried via reqCtx
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: build request: %w", ErrFetch, err)
	}
	req.Header.Set("Accept", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: %s: %w", ErrFetch, rawURL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxDocBytes))
	if err != nil {
		return 0, nil, nil, fmt.Errorf("%w: read body: %w", ErrFetch, err)
	}
	return resp.StatusCode, resp.Header, body, nil
}
