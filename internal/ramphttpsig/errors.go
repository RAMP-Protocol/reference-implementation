package ramphttpsig

import "errors"

// The conditions under which this transport will not sign a request, as
// sentinels a caller matches with errors.Is rather than by reading text.
//
// They are here rather than beside the code that returns them because both are
// read far from it: the one that matters most is recognized at the boundary that
// renders a message for an agent, several wrapping layers above RoundTrip.

// ErrUnusableKey is returned when the key a request would be signed with cannot
// be used: wrong length, or carrying a keyid that does not identify it. It is
// distinct from an error the KeySource itself returned (custody down, no active
// key, an unauthenticated caller), which is wrapped through so the caller can
// still match on the custody sentinels — the two call for different answers, an
// outage being retryable where malformed key material is not.
var ErrUnusableKey = errors.New("ramphttpsig: unusable signing key")

// ErrNoSigningKey is the condition EVERY failure to produce the key a request is
// signed with carries, whatever the underlying cause: custody down, no active
// key, an unauthenticated caller, or key material this transport will not sign
// with.
//
// It exists because a caller at the far end of the call has no other way to
// recognize the condition. A failure here surfaces from inside RoundTrip, so
// net/http wraps it in a *url.Error and the RPC layer above wraps that again in
// its own transport error — by the time it reaches the boundary that renders a
// message for the agent, every type that named the condition is buried and only
// the sentinel chain survives. Two things turn on recognizing it there: the
// failure gets the same class as one a caller resolving its own key reports, and
// its cause is kept out of the agent-facing message, because these causes
// describe this service's own key store rather than anything the agent did.
//
// It accompanies the specific cause rather than replacing it. The keystore
// sentinels and ErrUnusableKey stay reachable through errors.Is, so a caller
// that needs the finer answer — retry an outage, page an operator for a denial —
// still gets it.
var ErrNoSigningKey = errors.New("ramphttpsig: no usable signing key for this request")
