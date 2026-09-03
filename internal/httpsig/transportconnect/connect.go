// Package transportconnect adapts httpsig gate rejections to Connect-over-HTTP
// responses and the service audit vocabulary.
//
// It is the transport-aware seam deliberately kept OUT of the protocol-pure
// internal/httpsig package (Architecture Rules 5 and 9): httpsig verifies RFC
// 9421 signatures and returns sentinel errors only; this package maps those
// sentinels to Connect codes, HTTP statuses, and the REJECTED_* audit tokens a
// Connect-over-HTTP service emits. A non-Connect consumer of httpsig does not
// pull in connectrpc.
//
// It does NOT own how a refusal is written. The SDK's server binding exports
// that — connectserver.RejectCode, IsBodyTooLarge and WriteReject — and every
// function here that answers a protocol-shaped question defers to it. What
// stays is the part the SDK cannot know: this repository's own gate sentinels,
// which are distinct error objects from the SDK's, and the two audit
// vocabularies the services emit.
package transportconnect

import (
	"errors"
	"net/http"

	connect "connectrpc.com/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
)

// RejectCode maps a rejection at the verify seam to the Connect code returned to
// the client.
//
// One arm is answered here and the rest is the SDK's. The app-owned gate in
// internal/httpsig returns httpsig.ErrTooManyHops, which is a different error
// object from the helpers.ErrTooManyHops the SDK keys on — errors.Is between
// the two is false — so a hop-budget rejection from that gate would classify as
// an authentication failure and be answered 401 instead of 429. Every other
// input, the over-cap body included, is the SDK's judgement, and asking it is
// what keeps the two mounts answering alike.
func RejectCode(err error) connect.Code {
	if errors.Is(err, httpsig.ErrTooManyHops) {
		return connect.CodeResourceExhausted
	}
	return connectserver.RejectCode(err)
}

// IsBodyTooLarge reports whether err is net/http's over-cap signal from a read
// bounded by http.MaxBytesReader.
//
// It is the SDK's predicate under this package's name, because the branch it
// decides has callers here: a middleware that must tell, before it can answer,
// whether the read it just failed was a size refusal or a malformed request.
// Those two answer differently — one is a resource limit this package writes,
// the other a bad request the caller writes itself — so the predicate the
// branch turns on has to be the one the writer turns on.
func IsBodyTooLarge(err error) bool {
	return connectserver.IsBodyTooLarge(err)
}

// WriteError emits a Connect-compatible error response so Connect clients see a
// proper code (and matching HTTP status) instead of a raw status. The body and
// the code→status split are the SDK's: a body past the read cap is 413 (send
// less), a hop budget is 429 (send fewer, or slower), and anything else is 401.
// The 413 is a deliberate departure from Connect's own table, which is why one
// place decides it.
//
// Its signature matches httpsig.InterceptorOptions.OnReject, so it can be wired
// directly as the app gate's reject responder; the Exchange's catalog capture
// calls it for the over-cap read, which happens at the same point of the same
// seam. It answers those two verdicts only — a caller holding any other, such
// as a malformed read, writes that response itself.
func WriteError(w http.ResponseWriter, err error) {
	connectserver.WriteReject(w, RejectCode(err), err)
}

// OutcomeBodyTooLarge is the audit token for a request refused because its body
// passed the read cap, in the lowercase vocabulary the reject loggers emit
// beside the SDK's own signature / replay / broken_chain / hop_budget.
//
// The SDK's RejectReason has no value for it. That enum names the four
// authentication outcomes an RFC 9421 gate produces and defaults anything else
// to signature, which is the right default for an error the gate cannot place —
// but an over-cap body is not an authentication outcome at all, and the SDK's
// own response side says so, answering it 413 resource_exhausted rather than
// 401. Auditing it as a signature failure would send an operator after a key
// rotation for a caller that sent too much, which is the same misreport the
// response side was changed to stop making.
const OutcomeBodyTooLarge = "body_too_large"

// RejectAuditOutcome is the audit token for a verify-gate rejection, in the
// vocabulary the reject loggers emit. The four authentication outcomes come
// from the SDK's own classifier — the gate owns that judgement and no copy of
// it is kept here — and the one case the SDK's enum cannot express, a body past
// the read cap, is named rather than folded into the default.
func RejectAuditOutcome(err error) string {
	if IsBodyTooLarge(err) {
		return OutcomeBodyTooLarge
	}
	return connectserver.ClassifyReject(err).String()
}
