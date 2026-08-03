// Package testutil provides shared fixtures for rampwellknown tests: seeded
// (deterministic) signing keys, overlay-manifest / WBA-directory / revocation
// builders, and an httptest origin that serves all three documents. Keys are
// derived from a seed label so fixtures are reproducible and never depend on a
// non-deterministic RNG.
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
// JWK, valid over [notBefore, notAfter). The seed is derived from the seed label
// so the same label always yields the same key across test runs. Keys carry no
// kid — they are identified by their RFC 7638 thumbprint (rampwellknown.Thumbprint).
func NewSigningKey(seed string, notBefore, notAfter time.Time) (ed25519.PrivateKey, *rampwellknown.Key) {
	raw := make([]byte, ed25519.SeedSize)
	copy(raw, seed)
	priv := ed25519.NewKeyFromSeed(raw)
	pub, _ := priv.Public().(ed25519.PublicKey)
	return priv, rampwellknown.NewKey(pub, notBefore, notAfter)
}

// Manifest assembles a keyless commercial-overlay manifest value with the given
// role/domain; callers mutate the returned message for role-specific fields
// before marshaling. Identity keys live in the WBA directory (see WBAFile).
func Manifest(role rampwellknown.Role, domain string) *rampwellknown.Manifest {
	return &rampwellknown.Manifest{
		Ver:    rampwellknown.Version,
		Role:   role,
		Domain: domain,
	}
}

// WBAFile assembles a WBA directory carrying the given keys; callers set
// RevocationUrl before marshaling when exercising the revocation channel.
func WBAFile(keys ...*rampwellknown.Key) *rampwellknown.WBAFile {
	return &rampwellknown.WBAFile{Keys: keys}
}

// MarshalManifest renders m as canonical protojson (snake_case, full enums).
func MarshalManifest(m *rampwellknown.Manifest) []byte {
	raw, _ := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(m)
	return raw
}

// MarshalWBA renders a WBA directory as canonical protojson.
func MarshalWBA(f *rampwellknown.WBAFile) []byte {
	raw, _ := (protojson.MarshalOptions{UseProtoNames: true}).Marshal(f)
	return raw
}

// MarshalRevocation renders a KeyRevocationList (as_of + revoked thumbprints)
// as canonical protojson.
func MarshalRevocation(asOf time.Time, revoked ...string) []byte {
	list := &rampv1.KeyRevocationList{
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

// Client returns the HTTP client the rampwellknown tests use in place of
// http.DefaultClient. httptest.Server.Close() calls
// http.DefaultTransport.CloseIdleConnections() as a convenience, which drops
// every idle keep-alive connection pooled on the shared global transport. With
// the package's parallel tests each running an Origin and deferring Close(), one
// test's Close() can close an idle connection a concurrent test is reusing,
// surfacing as "connection broken: http: CloseIdleConnections called". A private
// transport with keep-alives disabled keeps no idle pool to race and never
// touches the global transport, so no peer's Close() can disturb an in-flight
// request.
func Client() *http.Client {
	return &http.Client{Transport: &http.Transport{DisableKeepAlives: true}}
}

// endpoint is one swappable well-known document endpoint: a body, an optional
// forced status code, an optional Cache-Control header, a request gate (to force
// concurrent callers to overlap inside a single in-flight fetch), and a hit
// counter. The manifest and WBA endpoints share this machinery.
type endpoint struct {
	contentType  string
	doc          atomic.Pointer[[]byte]
	status       atomic.Int32
	cacheControl atomic.Pointer[string]
	gate         atomic.Pointer[chan struct{}]
	hits         atomic.Int64
}

func (e *endpoint) serve(w http.ResponseWriter, _ *http.Request) {
	if g := e.gate.Load(); g != nil {
		<-*g
	}
	e.hits.Add(1)
	if code := e.status.Load(); code != 0 {
		w.WriteHeader(int(code))
		return
	}
	if cc := e.cacheControl.Load(); cc != nil {
		w.Header().Set("Cache-Control", *cc)
	}
	w.Header().Set("Content-Type", e.contentType)
	if p := e.doc.Load(); p != nil {
		_, _ = w.Write(*p)
	}
}

func (e *endpoint) block() (release func()) {
	ch := make(chan struct{})
	e.gate.Store(&ch)
	var once sync.Once
	return func() {
		once.Do(func() {
			e.gate.Store(nil)
			close(ch)
		})
	}
}

// Origin is an httptest server that serves an overlay manifest at
// /.well-known/ramp.json, a WBA directory at
// /.well-known/http-message-signatures-directory, and a revocation list at
// RevocationPath. Every document is swappable mid-test; the manifest and WBA
// endpoints can force a status code (Set*Status), the manifest endpoint can emit
// a Cache-Control header (SetCacheControl), count requests (Hits), and be gated
// (Block) to force concurrent callers to overlap inside one in-flight fetch.
type Origin struct {
	*httptest.Server
	manifest   *endpoint
	wba        *endpoint
	revocation atomic.Pointer[[]byte]
}

// RevocationPath is where Origin serves its KeyRevocationList. Re-exported from
// the production constant so fixtures and producers share one source.
const RevocationPath = rampwellknown.RevocationPath

// NewOrigin starts an Origin serving the given initial manifest bytes. The WBA
// and revocation documents start empty; set them with SetWBA / SetRevocation.
func NewOrigin(manifest []byte) *Origin {
	o := &Origin{
		manifest: &endpoint{contentType: "application/json"},
		wba:      &endpoint{contentType: "application/jwk-set+json"},
	}
	o.SetManifest(manifest)
	mux := http.NewServeMux()
	mux.HandleFunc(rampwellknown.Path, o.manifest.serve)
	mux.HandleFunc(rampwellknown.WBAPath, o.wba.serve)
	mux.HandleFunc(RevocationPath, o.serveRevocation)
	o.Server = httptest.NewServer(mux)
	return o
}

// SetManifest swaps the served overlay manifest document.
func (o *Origin) SetManifest(b []byte) { o.manifest.doc.Store(&b) }

// SetWBA swaps the served WBA directory document.
func (o *Origin) SetWBA(b []byte) { o.wba.doc.Store(&b) }

// SetRevocation swaps the served revocation document.
func (o *Origin) SetRevocation(b []byte) { o.revocation.Store(&b) }

// SetManifestStatus forces the manifest endpoint to return code (0 resets to 200).
func (o *Origin) SetManifestStatus(code int) {
	o.manifest.status.Store(int32(code)) //nolint:gosec // small status code
}

// SetWBAStatus forces the WBA endpoint to return code (0 resets to 200).
func (o *Origin) SetWBAStatus(code int) { o.wba.status.Store(int32(code)) } //nolint:gosec // small status code

// SetCacheControl sets the Cache-Control header the manifest endpoint emits on a
// 2xx response (empty clears it). Exercises the Cache's max-age TTL clamping.
func (o *Origin) SetCacheControl(value string) {
	if value == "" {
		o.manifest.cacheControl.Store(nil)
		return
	}
	o.manifest.cacheControl.Store(&value)
}

// Hits reports how many times the manifest endpoint has produced a response.
func (o *Origin) Hits() int64 { return o.manifest.hits.Load() }

// WBAHits reports how many times the WBA-directory endpoint has produced a
// response — used to assert a burst of unknown-keyid lookups coalesced into a
// bounded number of directory fetches.
func (o *Origin) WBAHits() int64 { return o.wba.hits.Load() }

// Block arms the manifest gate: every manifest request blocks until the returned
// release is called, so concurrent callers provably overlap inside a single
// in-flight fetch (single-flight). release is idempotent.
func (o *Origin) Block() (release func()) { return o.manifest.block() }

// RevocationURL is the absolute URL clients poll for the revocation list.
func (o *Origin) RevocationURL() string { return o.URL + RevocationPath }

func (o *Origin) serveRevocation(w http.ResponseWriter, _ *http.Request) {
	p := o.revocation.Load()
	if p == nil {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_, _ = w.Write(*p)
}

// Ptr returns a pointer to v; a small helper for optional proto fields in tests.
func Ptr[T any](v T) *T { return &v }
