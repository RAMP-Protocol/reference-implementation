// Package transportconnect adapts httpsig gate rejections to Connect-over-HTTP
// responses and the service audit vocabulary.
//
// It is the transport-aware seam deliberately kept OUT of the protocol-pure
// internal/httpsig package (Architecture Rules 5 and 9): httpsig verifies RFC
// 9421 signatures and returns sentinel errors only; this package maps those
// sentinels to Connect codes, HTTP statuses, and the REJECTED_* audit tokens a
// Connect-over-HTTP service emits. A non-Connect consumer of httpsig does not
// pull in connectrpc.
package transportconnect

import (
	"encoding/json"
	"errors"
	"net/http"

	connect "connectrpc.com/connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
)

// RejectCode maps a gate-rejection error to the Connect code returned to the
// client. A hop-budget rejection (ErrTooManyHops) is a resource/policy limit,
// not an authentication failure, so it surfaces as ResourceExhausted; every
// other rejection (bad signature, replay, broken chain, expiry) is an
// authentication failure.
func RejectCode(err error) connect.Code {
	if errors.Is(err, httpsig.ErrTooManyHops) {
		return connect.CodeResourceExhausted
	}
	return connect.CodeUnauthenticated
}

// httpStatus maps the two Connect codes the gate emits to their canonical HTTP
// statuses (Connect-over-HTTP: ResourceExhausted → 429, Unauthenticated → 401).
func httpStatus(code connect.Code) int {
	if code == connect.CodeResourceExhausted {
		return http.StatusTooManyRequests
	}
	return http.StatusUnauthorized
}

// WriteError emits a Connect-compatible error response so Connect clients see a
// proper code (and matching HTTP status) instead of a raw status. The code is
// derived from err via RejectCode. Its signature matches
// httpsig.InterceptorOptions.OnReject, so it can be wired directly as the gate's
// reject responder.
func WriteError(w http.ResponseWriter, err error) {
	code := RejectCode(err)
	ce := connect.NewError(code, err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(httpStatus(code))
	// json.Marshal escapes control bytes correctly (unlike a hand-rolled
	// quoter); the body shape mirrors Connect's unary error JSON.
	body, _ := json.Marshal(map[string]string{"code": code.String(), "message": ce.Message()})
	_, _ = w.Write(body)
}

// RejectOutcome classifies a gate-rejection error into an audit outcome token
// aligned with the service audit vocabulary (the REJECTED_* family used by the
// Exchange/Broker reject-logging and relay audit paths). It lets the OnError
// hook distinguish a hop-budget rejection from a signature/replay/chain failure
// without re-deriving the error kind at each call site.
func RejectOutcome(err error) string {
	switch {
	case errors.Is(err, httpsig.ErrTooManyHops):
		return "REJECTED_HOP_BUDGET"
	case errors.Is(err, httpsig.ErrReplayed):
		return "REJECTED_REPLAY"
	case errors.Is(err, httpsig.ErrBrokenSignatureChain):
		return "REJECTED_CHAIN"
	default:
		return "REJECTED_SIGNATURE"
	}
}
