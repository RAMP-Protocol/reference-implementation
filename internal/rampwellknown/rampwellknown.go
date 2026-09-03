// Package rampwellknown is the single consumer/producer library for the RAMP
// discovery surface, which after the WBA split spans two files every RAMP
// participant (agent, broker, exchange, publisher) serves:
//
//   - the pure Web Bot Auth directory at /.well-known/http-message-signatures-directory
//     (a ramp.v1.WBAFile — a JOSE JWK Set plus a directory-level revocation_url,
//     zero RAMP-specific fields), and
//   - the RAMP commercial overlay at /.well-known/ramp.json (a
//     ramp.v1.WellKnownManifest — role, authorized exchanges/contributors,
//     exchange capability fields; no identity keys).
//
// Keys live ONLY in the WBA file and are referenced elsewhere by RFC 7638
// thumbprint (the RFC 9421 keyid), never republished in the overlay. Both wire
// shapes are protojson with UseProtoNames=true — snake_case field names
// (not_before, revocation_url) and full enum value names (ROLE_PUBLISHER,
// PROVIDER_RELATIONSHIP_DIRECT). See the embedded schemas under schema/.
//
// The library provides:
//   - Fetch / FetchWBA: GET + schema-validate + protojson.Unmarshal a remote
//     overlay manifest or WBA directory.
//   - ActiveKeys / KeyByThumbprint / PublicKey: key-window selection and decoding
//     over a WBAFile's key set.
//   - Cache: TTL-bounded, single-flighted overlay-manifest cache keyed by domain.
//   - Loader: a WBA-directory cache plus a revocation_url poller, exposing
//     LookupKey (by thumbprint) with revoked/unknown/expired sentinels.
//   - server.Handler / server.WBAHandler (subpackage): builds + serves the
//     overlay manifest and WBA directory for a role.
package rampwellknown

import (
	"fmt"
	"net/url"
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// Version is the only RAMP protocol version this library produces or accepts.
// Consumers reject manifests whose ver differs (enforced by the schema).
//
// This versions the /.well-known/ramp.json DOCUMENT SCHEMA. It is a namespace
// deliberately separate from the version stamped on RPC envelope messages,
// which the SDK owns as helpers.ProtocolVersion, and ramp.proto says in as many
// words that the manifest version is not stamped from that constant.
//
// The two happen to read "1.0" today and must not be coupled, because they are
// enforced in opposite ways. This library rejects EVERY manifest whose ver
// differs, as the line above says and as schema/ramp-well-known.json enforces
// with a const: a "1.1" manifest fails ValidateManifest with ErrSchemaInvalid,
// not just a "2.0" one. The envelope ver is the reverse — advisory, never a
// rejection gate, and a receiver that checks it MUST NOT reject an unrecognised
// minor version. Coupling them would import one of those rules into the other's
// namespace, and the day either value moves it would do so silently.
const Version = "1.0"

// Path is the fixed request path every RAMP participant serves the commercial
// overlay manifest at.
const Path = "/.well-known/ramp.json"

// WBAPath is the fixed request path every RAMP participant serves its pure Web
// Bot Auth directory (WBAFile) at. It is the standard WBA directory location,
// readable by any off-the-shelf WBA verifier.
const WBAPath = "/.well-known/http-message-signatures-directory"

// RevocationPath is the conventional request path a participant serves its
// KeyRevocationList at, advertised to peers via WBAFile.revocation_url.
// Producers that serve a revocation channel mount it here; routing both the WBA
// directory and the revocation route off these constants keeps a path typo a
// compile error rather than an E2E-only failure.
const RevocationPath = "/.well-known/ramp-key-revocations.json"

// Manifest is the RAMP commercial overlay document. Alias (not a fresh type) so
// the generated proto accessors (GetRole, GetExchanges, …) are available.
type Manifest = rampv1.WellKnownManifest

// WBAFile is the Web Bot Auth directory: a JWK Set (keys) plus an optional
// directory-level revocation_url. Identity keys live here, never in Manifest.
type WBAFile = rampv1.WBAFile

// Key is a single Ed25519 JWK within a WBAFile's key set.
type Key = rampv1.JsonWebKey

// RevocationList is the revocation snapshot served at WBAFile.revocation_url.
// Its revoked entries are RFC 7638 thumbprints (base64url-no-pad).
type RevocationList = rampv1.KeyRevocationList

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

// ManifestURL builds the absolute /.well-known/ramp.json (commercial overlay)
// URL for a host. See wellKnownURL for the host-parsing contract.
func ManifestURL(host, scheme, port string) (string, error) {
	return wellKnownURL(host, scheme, port, Path)
}

// WBAURL builds the absolute /.well-known/http-message-signatures-directory
// (WBA directory) URL for a host. See wellKnownURL for the host-parsing contract.
func WBAURL(host, scheme, port string) (string, error) {
	return wellKnownURL(host, scheme, port, WBAPath)
}

// RevocationURL builds the absolute /.well-known/ramp-key-revocations.json
// (KeyRevocationList) URL for a host — the value a producer advertises in
// WBAFile.revocation_url. A consumer (Loader) host-anchors the advertised URL to
// the directory's own host and skips a cross-host one, so a producer serving a
// wildcard zone of per-agent hosts MUST derive this per host, not share one value.
// See wellKnownURL for the host-parsing contract.
func RevocationURL(host, scheme, port string) (string, error) {
	return wellKnownURL(host, scheme, port, RevocationPath)
}

// wellKnownURL builds the absolute URL for a fixed well-known path on a host.
// host may be a bare domain ("publisher.example"), a host:port, or a full origin
// ("https://publisher.example"). scheme defaults to "https" when host carries
// no scheme; port, when non-empty, is appended to a bare host (local/compose
// stacks serve on a non-default port).
func wellKnownURL(host, scheme, port, path string) (string, error) {
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
		u.Path = path
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
	return scheme + "://" + authority + path, nil
}
