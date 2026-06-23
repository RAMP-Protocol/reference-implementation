package proto

// Ver is the project-wide RAMP protocol version stamped on every RAMP proto
// message this system authors: ResourceQuery (Broker→Exchange), ResourceResponse
// and TransactionResponse (Exchange), and RAMPResponse (Broker). The agent-
// authored messages — TransactionRequest and UsageReport — are NOT stamped here:
// the agent originates and signs them and the Broker relays the bytes verbatim
// (it must not re-marshal, or it would break the agent's Content-Digest), so their
// ver is the agent's own contract, not this system's. It mirrors the spec version
// the pinned proto module ships under ("RAMP v1.0"). ramp.proto documents these per-message
// `ver` fields no more strongly than "RAMP protocol version." — none carries an
// inbound-validation mandate. Nothing in this system reads `ver` off an inbound
// wire message: it is write-only, so a value mismatch surfaces as a functional
// skew, not a rejection. Message authenticity rides on RFC 9421 httpsig plus
// ed25519 offer signatures, not on ver. Bump only in lockstep with a proto-module
// major-version bump in go.mod.
//
// This is the wire-protocol message version. The /.well-known/ramp.json manifest
// carries its own document-schema version (internal/rampwellknown.Version); that
// is the field the proto actually constrains — WellKnownManifest.ver is documented
// "MUST equal \"1.0\"; consumers REJECT unrecognised major versions." The two are
// deliberately separate namespaces and must not be coupled.
const Ver = "1.0"
