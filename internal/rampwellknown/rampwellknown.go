// Package rampwellknown is the single consumer/producer library for the
// canonical RAMP discovery surface served at /.well-known/ramp.json by every
// RAMP participant (agent, broker, exchange, publisher).
//
// The document is a ramp.v1.WellKnownManifest. Its JSON wire shape is
// protojson with UseProtoNames=true — snake_case field names (public_keys,
// not_before, invalidation_url) and full enum value names (ROLE_PUBLISHER,
// PROVIDER_RELATIONSHIP_DIRECT). See docs/reference/ramp-json-example in the
// protocol module and the embedded schemas under schema/.
//
// The library provides:
//   - Fetch: GET + schema-validate + protojson.Unmarshal a remote manifest.
//   - ActiveKeys / KeyByKid / PublicKey: key-window selection and decoding.
//   - Cache: TTL-bounded, single-flighted manifest cache keyed by domain.
//   - Loader: a Cache plus an invalidation_url revocation poller, exposing
//     LookupKey with revoked/unknown/expired sentinels.
//   - server.Handler (subpackage): builds + serves a manifest for a role.
package rampwellknown

import (
	"fmt"
	"net/url"
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// Version is the only RAMP protocol version this library produces or accepts.
// Consumers reject manifests whose ver differs (enforced by the schema).
const Version = "1.0"

// Path is the fixed request path every RAMP participant serves the manifest at.
const Path = "/.well-known/ramp.json"

// InvalidationPath is the conventional request path a participant serves its
// KeyInvalidationList at, advertised to peers via Manifest.invalidation_url.
// Producers that serve a revocation channel mount it here; routing both the
// manifest and the invalidation route off these constants keeps a path typo a
// compile error rather than an E2E-only failure.
const InvalidationPath = "/.well-known/ramp-invalidations.json"

// Manifest is the canonical discovery document. Alias (not a fresh type) so
// the generated proto accessors (GetRole, GetPublicKeys, …) are available.
type Manifest = rampv1.WellKnownManifest

// Key is a single inline Ed25519 JWK within Manifest.public_keys.
type Key = rampv1.JsonWebKey

// InvalidationList is the revocation snapshot served at invalidation_url.
type InvalidationList = rampv1.KeyInvalidationList

// Role identifies which kind of participant a Manifest describes.
type Role = rampv1.Role

// Role constants re-exported so callers need not import the proto package.
const (
	RoleUnspecified = rampv1.Role_ROLE_UNSPECIFIED
	RoleAgent       = rampv1.Role_ROLE_AGENT
	RoleExchange    = rampv1.Role_ROLE_EXCHANGE
	RoleBroker      = rampv1.Role_ROLE_BROKER
	RolePublisher   = rampv1.Role_ROLE_PUBLISHER
)

// ManifestURL builds the absolute /.well-known/ramp.json URL for a host. host
// may be a bare domain ("publisher.example"), a host:port, or a full origin
// ("https://publisher.example"). scheme defaults to "https" when host carries
// no scheme; port, when non-empty, is appended to a bare host (local/compose
// stacks serve the manifest on a non-default port).
func ManifestURL(host, scheme, port string) (string, error) {
	host = strings.TrimSpace(host)
	if host == "" {
		return "", fmt.Errorf("%w: empty host", ErrInvalidHost)
	}
	if strings.Contains(host, "://") {
		u, err := url.Parse(host)
		if err != nil {
			return "", fmt.Errorf("%w: %w", ErrInvalidHost, err)
		}
		if u.Host == "" {
			return "", fmt.Errorf("%w: no host in %q", ErrInvalidHost, host)
		}
		u.Path = Path
		u.RawQuery = ""
		return u.String(), nil
	}
	if scheme == "" {
		scheme = "https"
	}
	authority := host
	if port != "" && !strings.Contains(host, ":") {
		authority = host + ":" + port
	}
	return scheme + "://" + authority + Path, nil
}
