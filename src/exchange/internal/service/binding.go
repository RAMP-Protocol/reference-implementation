package service

import (
	"encoding/base64"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampthumbprint"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

// agentBinding carries the requesting agent's delivery-URL identity binding:
// the RFC 7638 thumbprint of the proven caller key in both the base64url-no-pad
// wire form (URL agent_id param + TransactionResponse.agent_identity_hash) and
// the raw 32-byte digest persisted to transaction_log (ADR-013 D4/17.6/17.8).
type agentBinding struct {
	thumbprint string
	digest     []byte
}

// agentBindingFor computes the binding from the cryptographically proven caller
// key. The key was verified by the httpsig middleware, so it is always a valid
// 32-byte Ed25519 key on this path; an invalid length is an internal invariant
// violation rather than a client error.
func agentBindingFor(caller Caller) (agentBinding, error) {
	sum, err := rampthumbprint.ThumbprintBytes(caller.PublicKey)
	if err != nil {
		return agentBinding{}, exchange.Wrap(exchange.KindInternal, err, "compute agent thumbprint")
	}
	digest := sum[:]
	return agentBinding{
		thumbprint: base64.RawURLEncoding.EncodeToString(digest),
		digest:     digest,
	}, nil
}
