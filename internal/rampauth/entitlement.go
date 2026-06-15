// Package rampauth holds transport-level helpers for RAMP request
// authentication that are independent of httpsig signature parsing.
//
// The entitlement biscuit rides alongside the RFC 9421 signature base
// and the Authorization Bearer JWT (ADR-002, ye6f-12). Carriage is
// three-tier per ADR-004:
//
//   - Tier 1 HTTP + Connect-Go — biscuit in the
//     X-RAMP-Entitlement-Biscuit header. Envelope and sub-message
//     fields MUST be empty.
//   - Tier 2 RAMPRequest envelope — biscuit in
//     RAMPRequest.entitlement_biscuit (proto field 8). Header and
//     sub-message fields MUST be empty.
//   - Tier 3 sub-message standalone — biscuit in the request
//     sub-message's own entitlement_biscuit field (ResourceQuery #12,
//     TransactionRequest #13, ListOffersRequest #3, AcceptOfferRequest
//     #3). Header and envelope MUST be empty.
//
// Precedence on intake is header > envelope > sub-message, but exactly
// one carrier MUST be populated — zero populated is Unauthenticated,
// more than one populated is InvalidArgument "conflicting biscuit
// carriers". ResolveBiscuit implements the rule so every service-layer
// caller shares one implementation.
package rampauth

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
)

// EntitlementHeader is the canonical X-RAMP-Entitlement-Biscuit header name.
const EntitlementHeader = "X-RAMP-Entitlement-Biscuit"

// MaxEntitlementHeaderBytes is the maximum accepted encoded header length.
// 8 KiB matches the ADR-002 wire-shape cap; requests exceeding this size
// are rejected with HTTP 431 (Request Header Fields Too Large).
const MaxEntitlementHeaderBytes = 8 * 1024

// Errors returned by the package surface. Callers map these to the
// transport-appropriate status: ErrHeaderTooLarge → 431;
// ErrInvalidBase64 → 400 (malformed request);
// ErrConflictingCarriers → connect.CodeInvalidArgument (three-tier
// rule violated — ADR-004).
var (
	// ErrHeaderTooLarge is returned when the encoded header exceeds the cap.
	ErrHeaderTooLarge = errors.New("rampauth: entitlement header exceeds 8 KiB")
	// ErrInvalidBase64 is returned when the header value is not a valid
	// base64url encoding. Biscuit chain verification is a separate concern;
	// malformed base64 is a wire-level bug.
	ErrInvalidBase64 = errors.New("rampauth: entitlement header not base64url")
	// ErrConflictingCarriers is returned by ResolveBiscuit when more than
	// one of (header, envelope, sub-message) carries a biscuit in the same
	// request. Callers surface this as InvalidArgument so operators can
	// distinguish a three-tier bug from a missing credential.
	ErrConflictingCarriers = errors.New("rampauth: conflicting biscuit carriers")
)

// ReadEntitlementBiscuit returns the raw biscuit bytes carried in
// X-RAMP-Entitlement-Biscuit. An absent or empty header returns (nil,
// nil) so callers can decide whether absence is legal for the RPC.
// The header is decoded as base64url (unpadded and padded both
// accepted), matching what the MCP shim emits and what ADR-002
// §Wire-shape specifies.
func ReadEntitlementBiscuit(r *http.Request) ([]byte, error) {
	if r == nil {
		return nil, nil
	}
	raw := r.Header.Get(EntitlementHeader)
	if raw == "" {
		return nil, nil
	}
	if len(raw) > MaxEntitlementHeaderBytes {
		return nil, fmt.Errorf("%w: %d bytes", ErrHeaderTooLarge, len(raw))
	}
	// Accept all four base64 variants the biscuit-go decoder is happy
	// with — clients in the wild emit any of: URL-safe unpadded
	// (canonical wire encoding, ADR-002 §Wire-shape), URL-safe padded,
	// standard unpadded, standard padded. URL-safe variants come first
	// because that is the canonical encoding; standard variants are a
	// fallback for clients (notably Python `base64.b64encode`) that
	// emit the +/ alphabet by default. Mirrors the multi-encoding
	// pattern in src/exchange/internal/delegation/verifier.go::decodeToken.
	for _, enc := range []*base64.Encoding{
		base64.RawURLEncoding,
		base64.URLEncoding,
		base64.RawStdEncoding,
		base64.StdEncoding,
	} {
		if out, err := enc.DecodeString(raw); err == nil {
			return out, nil
		}
	}
	return nil, fmt.Errorf("%w: header not base64 (tried url-safe + std)",
		ErrInvalidBase64)
}

// entitlementCtxKey carries the parsed biscuit bytes through the
// Connect-Go handler chain after the transport interceptor reads them off
// the request.
type entitlementCtxKey struct{}

// WithEntitlementBiscuit returns ctx annotated with the parsed biscuit
// bytes. nil/empty biscuits are stored as the nil-slice so downstream
// callers can distinguish "missing" from "present but empty".
func WithEntitlementBiscuit(ctx context.Context, biscuit []byte) context.Context {
	return context.WithValue(ctx, entitlementCtxKey{}, biscuit)
}

// EntitlementBiscuitFromContext returns the biscuit stashed by the
// transport interceptor, or nil when no biscuit was supplied.
func EntitlementBiscuitFromContext(ctx context.Context) []byte {
	v, _ := ctx.Value(entitlementCtxKey{}).([]byte)
	return v
}

// ResolveBiscuit applies the ADR-004 three-tier precedence rule to pick
// the authoritative biscuit bytes for a request.
//
// Arguments correspond to the three carriers in precedence order:
// header (Tier 1), envelope (Tier 2), subMessage (Tier 3). A
// zero-length slice is treated as absent to handle the protobuf-default
// case for unset `optional bytes`.
//
//	zero carriers populated → nil, nil     (no credential; caller
//	                                        surfaces Unauthenticated)
//	one carrier populated   → bytes, nil   (that carrier is canonical)
//	>1 carriers populated   → nil, ErrConflictingCarriers
//
// The three-tier intake is strict: more than one populated carrier
// returns ErrConflictingCarriers REGARDLESS of whether the bytes are
// byte-identical. ADR-005 §"Intake rule at Exchange" pins this:
// "tolerant fallback would hide integration bugs at bridges." Bridges
// (Broker, MCP shim, future envelope-aware relays) MUST move the
// biscuit from inbound to outbound tier AND MUST clear the inbound
// tier; a sender that populates two tiers — even with identical bytes —
// has a bug and the strict rule surfaces it at the first hop instead
// of letting it propagate.
func ResolveBiscuit(header, envelope, subMessage []byte) ([]byte, error) {
	hasHeader := len(header) > 0
	hasEnvelope := len(envelope) > 0
	hasSubMessage := len(subMessage) > 0
	populated := 0
	for _, present := range []bool{hasHeader, hasEnvelope, hasSubMessage} {
		if present {
			populated++
		}
	}
	switch {
	case populated == 0:
		return nil, nil
	case populated > 1:
		return nil, ErrConflictingCarriers
	case hasHeader:
		return header, nil
	case hasEnvelope:
		return envelope, nil
	default:
		return subMessage, nil
	}
}

// CanonicalBiscuit resolves the authoritative biscuit bytes for a
// service-layer call by combining the header bytes already stashed in
// ctx (by EntitlementMiddleware) with the envelope and sub-message
// bytes the caller supplies from its typed proto getter. Callers that
// operate on an RPC with no envelope or sub-message slot pass nil for
// the absent tier(s).
//
// On conflict returns ErrConflictingCarriers so the caller can surface
// connect.CodeInvalidArgument "conflicting biscuit carriers".
func CanonicalBiscuit(ctx context.Context, envelope, subMessage []byte) ([]byte, error) {
	return ResolveBiscuit(EntitlementBiscuitFromContext(ctx), envelope, subMessage)
}
