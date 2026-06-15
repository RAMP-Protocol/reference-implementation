// Package testutil provides shared fixtures for rampwellknown tests: seeded
// (deterministic) signing keys, manifest/invalidation builders, and an
// httptest origin that serves both documents. Keys are derived from the kid so
// fixtures are reproducible and never depend on a non-deterministic RNG.
package testutil

import (
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// NewSigningKey returns a deterministic Ed25519 private key plus its published
// JWK for kid, valid over [notBefore, notAfter). The seed is derived from kid
// so the same kid always yields the same key across test runs.
func NewSigningKey(kid string, notBefore, notAfter time.Time) (ed25519.PrivateKey, *rampwellknown.Key) {
	seed := make([]byte, ed25519.SeedSize)
	copy(seed, kid)
	priv := ed25519.NewKeyFromSeed(seed)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return priv, rampwellknown.NewKey(kid, pub, notBefore, notAfter)
}

// Manifest assembles a manifest value with the given role/domain/keys; callers
// mutate the returned message for role-specific fields before marshaling.
func Manifest(role rampwellknown.Role, domain string, keys ...*rampwellknown.Key) *rampwellknown.Manifest {
	return &rampwellknown.Manifest{
		Ver:        rampwellknown.Version,
		Role:       role,
		Domain:     domain,
		PublicKeys: keys,
	}
}

// MarshalManifest renders m as canonical protojson (snake_case, full enums).
func MarshalManifest(m *rampwellknown.Manifest) []byte {
	raw, _ := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(m)
	return raw
}

// MarshalInvalidation renders a KeyInvalidationList as canonical protojson.
func MarshalInvalidation(asOf time.Time, revoked ...string) []byte {
	list := &rampv1.KeyInvalidationList{
		AsOf:    timestamppb.New(asOf.UTC()),
		Revoked: revoked,
	}
	raw, _ := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(list)
	return raw
}

// PublisherExchange builds an AuthorizedExchange entry for a publisher manifest.
func PublisherExchange(domain, endpoint string, rel rampv1.ProviderRelationship) *rampv1.AuthorizedExchange {
	return &rampv1.AuthorizedExchange{Domain: domain, Endpoint: endpoint, Relationship: rel}
}

// Origin is an httptest server that serves a manifest at /.well-known/ramp.json
// and a revocation list at /.well-known/ramp-invalidations.json. Both documents
// are swappable mid-test; ManifestStatus overrides the manifest response code
// (e.g. 404) when non-zero. The manifest endpoint counts requests (Hits), can
// emit a Cache-Control header (SetCacheControl), and can be gated (Block) to
// force concurrent callers to overlap inside one in-flight fetch.
type Origin struct {
	*httptest.Server
	manifest       atomic.Pointer[[]byte]
	invalidation   atomic.Pointer[[]byte]
	manifestStatus atomic.Int32
	cacheControl   atomic.Pointer[string]
	gate           atomic.Pointer[chan struct{}]
	hits           atomic.Int64
}

// InvalidationPath is where Origin serves its KeyInvalidationList. Re-exported
// from the production constant so fixtures and producers share one source.
const InvalidationPath = rampwellknown.InvalidationPath

// NewOrigin starts an Origin serving the given initial manifest bytes.
func NewOrigin(manifest []byte) *Origin {
	o := &Origin{}
	o.SetManifest(manifest)
	mux := http.NewServeMux()
	mux.HandleFunc(rampwellknown.Path, o.serveManifest)
	mux.HandleFunc(InvalidationPath, o.serveInvalidation)
	o.Server = httptest.NewServer(mux)
	return o
}

// SetManifest swaps the served manifest document.
func (o *Origin) SetManifest(b []byte) { o.manifest.Store(&b) }

// SetInvalidation swaps the served revocation document.
func (o *Origin) SetInvalidation(b []byte) { o.invalidation.Store(&b) }

// SetManifestStatus forces the manifest endpoint to return code (0 resets to 200).
func (o *Origin) SetManifestStatus(code int) { o.manifestStatus.Store(int32(code)) } //nolint:gosec // small status code

// SetCacheControl sets the Cache-Control header the manifest endpoint emits on a
// 2xx response (empty clears it). Exercises the Cache's max-age TTL clamping.
func (o *Origin) SetCacheControl(value string) {
	if value == "" {
		o.cacheControl.Store(nil)
		return
	}
	o.cacheControl.Store(&value)
}

// Hits reports how many times the manifest endpoint has produced a response.
func (o *Origin) Hits() int64 { return o.hits.Load() }

// Block arms a gate: every manifest request blocks until the returned release is
// called, so concurrent callers provably overlap inside a single in-flight fetch
// (single-flight). release is idempotent; call it once to unblock and disarm.
func (o *Origin) Block() (release func()) {
	ch := make(chan struct{})
	o.gate.Store(&ch)
	var once sync.Once
	return func() {
		once.Do(func() {
			o.gate.Store(nil)
			close(ch)
		})
	}
}

// InvalidationURL is the absolute URL clients poll for the revocation list.
func (o *Origin) InvalidationURL() string { return o.URL + InvalidationPath }

func (o *Origin) serveManifest(w http.ResponseWriter, _ *http.Request) {
	if g := o.gate.Load(); g != nil {
		<-*g
	}
	o.hits.Add(1)
	if code := o.manifestStatus.Load(); code != 0 {
		w.WriteHeader(int(code))
		return
	}
	if cc := o.cacheControl.Load(); cc != nil {
		w.Header().Set("Cache-Control", *cc)
	}
	w.Header().Set("Content-Type", "application/json")
	if p := o.manifest.Load(); p != nil {
		_, _ = w.Write(*p)
	}
}

func (o *Origin) serveInvalidation(w http.ResponseWriter, _ *http.Request) {
	p := o.invalidation.Load()
	if p == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(*p)
}

// Ptr returns a pointer to v; a small helper for optional proto fields in tests.
func Ptr[T any](v T) *T { return &v }
