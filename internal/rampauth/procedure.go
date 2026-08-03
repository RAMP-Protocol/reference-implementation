// Package rampauth holds transport-level helpers for RAMP request
// authentication that are independent of httpsig signature parsing: the
// “/ramp.“ procedure predicate that gates outbound RFC 9421 signing
// (IsRAMPProcedure) and the Bearer-JWT claim helpers (jwtclaims.go).
package rampauth

import (
	"net/http"
	"strings"
)

// RAMPProcedurePrefix is the URL-path prefix that marks a Connect RPC as a RAMP
// procedure (“/ramp.v1.<Service>/<Method>“). It is the single boundary both the
// server-side verify seam and the client-side sign predicate key off, so the two
// cannot drift.
const RAMPProcedurePrefix = "/ramp."

// IsRAMPProcedure reports whether r targets a RAMP procedure — the predicate that
// gates outbound RFC 9421 signing (core.WithSignPredicate) to the RAMP namespace,
// mirroring the /ramp. boundary the server-side verify seam enforces. A request
// with no URL is treated as out-of-namespace (not signed).
func IsRAMPProcedure(r *http.Request) bool {
	return r.URL != nil && strings.HasPrefix(r.URL.Path, RAMPProcedurePrefix)
}
