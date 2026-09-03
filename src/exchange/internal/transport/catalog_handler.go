package transport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"net/http"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig/transportconnect"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/keypolicy"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/agentreg"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// maxCatalogBodyBytes bounds the raw PushResources body CatalogSignatureMiddleware
// buffers before any verification. The endpoint is pre-auth — the RFC 9421
// signature is checked in the handler, over the exact bytes the middleware
// captured — so the read runs before the caller is known, and an unbounded one
// would let an unauthenticated caller exhaust memory. It is the same value as
// the message cap CatalogMountOptions puts on the handler, so the raw body and
// the decoded message are bounded alike on this mount, which is what
// connectserver.WithMaxRequestBytes does for the ExchangeService mount from
// one number.
const maxCatalogBodyBytes int64 = MaxRPCReadBytes

// httpContextKey holds the raw http.Request + captured body bytes so the
// CatalogHandler can enforce RFC 9421 signature verification without requiring
// the service layer to know about transport. Populated by
// CatalogSignatureMiddleware and consumed by CatalogHandler.PushResources. The
// captured body is needed because Connect drains request.Body to decode the
// message before the handler runs, so verification must re-supply the bytes.
type httpContextKey struct{}

type catalogSignatureCtx struct {
	request *http.Request
	body    []byte
}

// CatalogSignatureMiddleware captures the raw http.Request and body bytes for
// ramp.v1.CatalogService requests and threads them through the context so the
// downstream Connect handler can verify RFC 9421 HTTP Message Signatures.
//
// Only the CatalogService path is wrapped; other services are left untouched
// so their body streams are not buffered.
func CatalogSignatureMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isCatalogPush(r) {
			next.ServeHTTP(w, r)
			return
		}
		// Bound the read: the endpoint is pre-auth, so an unbounded body would
		// let an unauthenticated caller exhaust the Exchange's memory before the
		// signature is checked. MaxBytesReader REFUSES a body past the cap; the
		// LimitReader that used to sit here truncated it instead, and the
		// truncated bytes were then misreported downstream: as a malformed
		// message when they no longer decoded (a JSON push cut short answers
		// InvalidArgument, "unexpected EOF"), or as an invalid signature when
		// they still did and failed the content digest — never as the size
		// limit the caller had actually hit.
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCatalogBodyBytes))
		if err != nil {
			writeCatalogReadError(w, r, err)
			return
		}
		_ = r.Body.Close()
		r.Body = io.NopCloser(bytes.NewReader(body))
		ctx := context.WithValue(r.Context(), httpContextKey{}, &catalogSignatureCtx{request: r, body: body})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// writeCatalogReadError answers a failed capture read. A body past the cap is a
// resource limit, not an authentication failure: it is answered as Connect's
// resource_exhausted with a 413, so a caller learns the one refusal it fixes by
// sending less. transportconnect.WriteError hands that answer to the SDK's own
// reject writer, the same one the verify face uses on the ExchangeService
// mount, so the two mounts answer the same body the same way by construction
// rather than by being kept level.
//
// The size refusal is also AUDITED, through the same observer the
// ExchangeService mount registers as its reject hook. That mount gets the line
// from the SDK's verify seam; this one has no seam to hook, so it calls the
// observer itself. Without it the refusal left no trace at all, and the
// operator documentation describes an outcome=body_too_large line on this
// endpoint that nothing wrote.
//
// Any other read failure is a malformed request and is answered here, as plain
// text with a 400. It deliberately does not go through the writer above: that
// writer answers the verify seam's two verdicts and refuses anything else 401,
// so routing a malformed read through it would turn a 400 into a 401. It is
// deliberately not audited either: the reject vocabulary has no value for a
// malformed read, so it would classify as the default, signature — the exact
// misreport the body_too_large token was added to stop, sending an operator
// after a key rotation for a caller whose connection broke mid-body.
func writeCatalogReadError(w http.ResponseWriter, r *http.Request, err error) {
	if transportconnect.IsBodyTooLarge(err) {
		LogHTTPSigReject(r, err)
		transportconnect.WriteError(w, err)
		return
	}
	http.Error(w, "read body: "+err.Error(), http.StatusBadRequest)
}

func isCatalogPush(r *http.Request) bool {
	return r.Method == http.MethodPost &&
		r.URL != nil &&
		r.URL.Path == rampconnect.CatalogServicePushResourcesProcedure
}

// CatalogHandler adapts CatalogService to the generated connect interface.
type CatalogHandler struct {
	rampconnect.UnimplementedCatalogServiceHandler
	svc      *service.CatalogService
	registry agentreg.Registry
}

// NewCatalogHandler wires the handler. registry is used for Gate 1
// (RFC 9421 caller-signature verification with lazy self-signup).
func NewCatalogHandler(svc *service.CatalogService, registry agentreg.Registry) *CatalogHandler {
	return &CatalogHandler{svc: svc, registry: registry}
}

// PushResources handles ramp.v1.CatalogService/PushResources.
func (h *CatalogHandler) PushResources(
	ctx context.Context,
	req *connect.Request[rampv1.PushResourcesRequest],
) (*connect.Response[rampv1.PushResourcesResponse], error) {
	// Every return goes through catalogFaultError, not bare ToConnect: the Kind→Code
	// table is only half the answer. The other half is the ErrorDetail envelope —
	// the domain a client filters on and the field name a refusal names — and a
	// path that skips it silently discards both.
	if err := canonicalizeCallerID(ctx, req.Msg); err != nil {
		return nil, catalogFaultError(err)
	}
	if err := h.verifyCallerSignature(ctx, req.Msg.GetCallerId()); err != nil {
		return nil, catalogFaultError(err)
	}
	out, err := h.svc.PushResources(ctx, req.Msg)
	if err != nil {
		return nil, catalogFaultError(err)
	}
	return connect.NewResponse(out), nil
}

// canonicalizeCallerID rewrites msg.CallerId to the canonical directory host, in
// place, so the two gates this request passes read one value rather than two
// spellings of it.
//
// Gate 1 (verifyCallerSignature) resolves the caller's key through agentreg,
// which canonicalizes internally. Gate 2 (the per-entry contributor check)
// compares caller_id against the publisher manifest's contributor domains
// VERBATIM. Left raw, the two disagreed: a publisher posting
// "https://pub.example" authenticated successfully as pub.example and was then
// refused with caller_not_in_catalog_contributors — a rejection naming a
// condition it demonstrably satisfies. Rewriting at the edge is the same shape
// agents/register and the Broker's resolve input already use, and agentreg's own
// storageKey doc names this caller_id as one of the inputs that normalization
// exists for.
//
// Only the CALLER side is folded HERE. The manifest side is folded too, but by
// the comparison itself — AuthorizesContributor takes the identity rule as a
// parameter and applies it to both. Folding one side only made the check
// asymmetric and refused every publisher that had spelled its own contributor
// entry with a scheme, in mixed case, with a trailing dot, or with :443.
//
// Folding does not widen who counts as a contributor, which is what this comment
// used to claim: distinct hosts keep distinct identities, so it removes
// differences of spelling and nothing else.
//
// An empty caller_id passes through untouched. It is a missing identity rather
// than an unregistrable one, and both gates already have their own answers for
// it — Gate 1 refuses self-signup without a caller_id, Gate 2 refuses the push.
func canonicalizeCallerID(ctx context.Context, msg *rampv1.PushResourcesRequest) error {
	raw := msg.GetCallerId()
	if raw == "" {
		return nil
	}
	callerID, err := agentid.FromDirectory(raw)
	if err != nil {
		// InvalidArgument, matching the sibling refusals on the Broker's agent_id
		// and on /agents/register: the caller sent a field that is not a host. That
		// is a malformed argument, not a failure to authenticate — and answering it
		// as the latter told a caller to go looking at its keys.
		//
		// The message is curated and the cause is logged rather than returned. The
		// wrapped chain names the parser and the rule that rejected the value, which
		// helps an operator and tells an unauthenticated stranger about our
		// internals; /agents/register already draws that line the same way.
		reqctx.FromContext(ctx).WarnContext(ctx, "catalog caller_id is not a host",
			"caller_id", raw, "err", err)
		return exchange.Newf(exchange.KindInvalidRequest,
			"caller_id does not name a host").WithField("caller_id")
	}
	msg.CallerId = callerID
	return nil
}

// verifyCallerSignature enforces Gate 1. The middleware must have populated
// the context with raw body + headers; verification is retried once after a
// manifest-driven self-signup attempt when keyid is unknown.
//
// Errors are constructed through the domain Kind vocabulary (exchange.Newf /
// exchange.Wrap) and PushResources funnels them through exchange.ToConnect, so
// the signature gate shares the single Kind→connect.Code mapping table with
// every other handler path instead of hand-picking connect codes inline
// (one canonical Kind→code mapping, never per-site). The emitted codes are UNCHANGED by this
// refactor: a sig-verify / self-signup failure is KindUnauthenticated (→
// CodeUnauthenticated) and the missing-middleware wiring fault is KindInternal
// (→ CodeInternal), exactly as the prior inline connect.NewError calls produced.
func (h *CatalogHandler) verifyCallerSignature(ctx context.Context, callerID string) error {
	sigCtx, ok := ctx.Value(httpContextKey{}).(*catalogSignatureCtx)
	if !ok || sigCtx == nil {
		return exchange.Newf(exchange.KindInternal, "catalog: signature middleware missing")
	}
	// VerifyRequest (not the legacy Verify) so the catalog push is held to the
	// same RFC 9421 policy as every other signed surface: required covered
	// components (@method, @target-uri, content-digest, authorization,
	// signature-agent) AND the created/expires freshness window. The catalog
	// signer already covers that set and stamps created/expires, so this is a
	// tightening, not a break.
	//
	// After the WBA split the signature keyid is a thumbprint, so the caller's
	// key is NOT resolvable by keyid in the agents table. It is resolved by the
	// contributor's caller_id (its domain / Signature-Agent directory), which is
	// what the agents table (and the Gate-1 self-signup TOFU-pin) is keyed on:
	// the closure ignores the thumbprint keyid and returns the key pinned for
	// callerID, so VerifyRequestResolved checks the signature against the published key.
	resolver := keypolicy.ResolverFunc(func(ctx context.Context, _ string) (ed25519.PublicKey, error) {
		return h.registry.LookupPublicKey(ctx, callerID)
	})
	// helpers.VerifyRequestResolved is pure: body is supplied explicitly so
	// request.Body (already drained by Connect) need not be re-seated.
	verify := func() error {
		_, err := helpers.VerifyRequestResolved(ctx, sigCtx.request, sigCtx.body, resolver, helpers.VerifyOptions{})
		return err
	}
	if err := verify(); err != nil {
		return h.selfSignupOnVerifyFailure(ctx, callerID, err, verify)
	}
	return nil
}

// selfSignupOnVerifyFailure handles a failed caller-signature verification. Two
// cases resolve the same way — re-learn the caller's currently-published key and
// re-verify — differing only in fetch-error handling:
//
//   - First contact (agentreg.ErrUnknown: no pinned key) → firstContactSelfSignup
//     registers the key from the publisher's WBA directory. A fetch failure is
//     surfaced (caller fault → Unauthenticated, transient → Unavailable) because
//     the fetch is required to establish identity at all.
//   - Known caller whose signature no longer matches the pinned key (key
//     rotation) → a bounded/debounced RefreshDirectoryKey re-pins, then re-verify.
//     A refresh failure is NOT surfaced: it is logged and we re-verify against the
//     best key available, denying on mismatch, so an unreachable directory can't
//     upgrade an impersonation attempt into a retryable Unavailable.
//
// The retry-on-unknown shape is intentionally app-level, not an SDK hook: it
// occurs only on this path, and CatalogService mounts raw (bypassing the SDK
// connectserver verify seam) for per-contributor verification, so a
// verify-with-self-signup hook would redesign the catalog path for one caller.
//
// Failures are expressed in the domain Kind vocabulary so PushResources'
// exchange.ToConnect owns the single Kind→connect.Code mapping (Architecture
// Rule 9).
func (h *CatalogHandler) selfSignupOnVerifyFailure(
	ctx context.Context, callerID string, verifyErr error, verify func() error,
) error {
	if callerID == "" {
		return exchange.Wrap(exchange.KindUnauthenticated, verifyErr, "catalog: unknown caller, no caller_id for self-signup")
	}
	if errors.Is(verifyErr, agentreg.ErrUnknown) {
		return h.firstContactSelfSignup(ctx, callerID, verify)
	}
	if err := h.registry.RefreshDirectoryKey(ctx, callerID); err != nil {
		reqctx.FromContext(ctx).WarnContext(ctx,
			"catalog: caller key re-pin failed", "caller_id", callerID, "err", err)
	}
	if err := verify(); err != nil {
		return exchange.Wrap(exchange.KindUnauthenticated, err, "catalog: caller signature invalid")
	}
	return nil
}

// firstContactSelfSignup registers a caller with no pinned key from its WBA
// directory (trust-on-first-fetch) and re-verifies. agentreg.IsCallerFault is
// the single source of the caller-fault vs transient split, shared with
// service.mapLazyRegisterError.
func (h *CatalogHandler) firstContactSelfSignup(
	ctx context.Context, callerID string, verify func() error,
) error {
	if regErr := h.registry.RegisterFromDirectory(ctx, callerID, callerID); regErr != nil {
		if agentreg.IsCallerFault(regErr) {
			return exchange.Wrap(exchange.KindUnauthenticated, regErr, "catalog: caller self-signup failed")
		}
		return exchange.Wrap(exchange.KindUnavailable, regErr, "catalog: caller self-signup unavailable")
	}
	// Provable evidence that the key was learned via the well-known fetch (not a
	// DB pre-seed) — the e2e catalog-trust test asserts this line, and it only
	// fires on a cache miss, so its presence proves first-contact self-signup.
	reqctx.FromContext(ctx).InfoContext(ctx,
		"catalog: caller self-signup from well-known manifest", "caller_id", callerID)
	if err := verify(); err != nil {
		return exchange.Wrap(exchange.KindUnauthenticated, err, "catalog: caller signature invalid after self-signup")
	}
	return nil
}
