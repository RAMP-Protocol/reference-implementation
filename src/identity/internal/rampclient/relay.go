package rampclient

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampreason"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// relayExecutePath is the Broker's execute-relay route. It is NOT a Connect
// /ramp.* path: the agent posts a TransactionRequest here and the Broker
// re-packages it per exchange. The one RAMP call this package makes by hand.
const relayExecutePath = "/broker/v1/exchange/execute"

// relayRequestJSON marshals the outbound TransactionRequest with snake_case
// proto field names. The RAMP wire is snake_case proto-JSON, and protojson's
// default writes the camelCase json_name alias instead — which made this the one
// proto-JSON producer in the tree whose output does not match what every other
// one emits (the Broker's own relay writer, the well-known builders, the MCP
// tool results all write proto names). The Broker decodes both spellings, so no
// behavior changes at the far end; what changes is that a reader which accepts
// only the canonical spelling can now read this leg.
//
// Deliberately NOT the emit-unpopulated codec the Broker's relay WRITER uses.
// That codec is the response policy. This is a request, and the relay route
// buffers it under a 64 KiB pre-auth cap; emitting every zero-valued field of
// each embedded signed Offer would push a legitimate batch toward that cap and
// buy nothing, because the receiver decodes the same message either way.
var relayRequestJSON = protojson.MarshalOptions{UseProtoNames: true}

// maxRelayResponseBytes bounds the relay response read. A TransactionResponse for
// a realistic batch is small; the bound is a guard against a peer that answers
// with an unbounded body, not a real size limit.
const maxRelayResponseBytes = 4 << 20 // 4 MiB

// correlationTransport stamps the correlation id on every outbound request. It
// sits UNDER the signing transport, so the header is added before signing sees
// the request; the id is outside the RAMP covered set either way, so it does not
// affect the signature.
type correlationTransport struct{ base http.RoundTripper }

func (t correlationTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Header.Get(reqctx.HeaderRequestID) == "" {
		req = req.Clone(req.Context())
		req.Header.Set(reqctx.HeaderRequestID, reqctx.IDOrNew(req.Context()))
	}
	return t.base.RoundTrip(req)
}

// relayTargetOf marks the relay POST as RAMP-signed traffic (WithRAMPTargets).
//
// The predicate is derived from the relay URL actually in use rather than
// matching relayExecutePath outright: relayURL is BrokerURL with the path
// appended, so a Broker mounted under a prefix (https://gw.example/broker,
// behind a gateway) produces /broker/broker/v1/exchange/execute. An exact match
// on the bare path would miss that, the request would fall through to unsigned,
// and the Broker would refuse it with a signature error naming nothing useful.
func relayTargetOf(relayURL string) func(*http.Request) bool {
	path := relayExecutePath
	if u, err := url.Parse(relayURL); err == nil && u.Path != "" {
		path = u.Path
	}
	return func(req *http.Request) bool {
		return req.URL != nil && req.URL.Path == path
	}
}

// accountProcedures are the two RPC procedures this client sends to an Exchange.
// The generated constructor appends one of them to whatever endpoint it was
// built on, so they are the SUFFIX of every account request's path.
var accountProcedures = []string{
	rampv1connect.ExchangeServiceRegisterProcedure,
	rampv1connect.ExchangeServiceGetAccountStatusProcedure,
}

// accountTargetOf marks an account RPC sent to an endpoint carrying a path
// prefix as RAMP-signed traffic.
//
// The transport's own rule reads the path's PREFIX: a path starting "/ramp." is
// a RAMP RPC. That holds while the endpoint is a bare origin, and it stops
// holding the moment an Exchange advertises one with a path. This branch made
// exactly that possible: the account legs now dial an endpoint resolved from the
// target Exchange's own manifest, where before it came from a setting an
// operator wrote once. "https://exchange.example/api" produces the path
// "/api/ramp.v1.ExchangeService/Register", the prefix test fails, and no profile
// claims the request — so it goes out unsigned, carrying the operator's
// registration details, and nothing on this side reports why. The far end fails
// closed, so the visible symptom is an Exchange behind a path prefix that can
// never be registered at.
//
// A path-prefixed endpoint is conformant. The pinned protocol module constrains
// a manifest's endpoint on host, port and userinfo, and the endpoint rule this
// client resolves through enforces those three, so such an endpoint arrives
// without objection.
//
// Matched by procedure SUFFIX rather than by looking for "/ramp." anywhere in
// the path: the two procedures below are the only ones this client sends, so
// this claims exactly its own traffic and cannot start signing a request to some
// other path that happens to contain those bytes. WithRAMPTargets only ADDS to
// the signed set, so nothing that is signed today can stop being signed by this.
func accountTargetOf(req *http.Request) bool {
	if req.URL == nil {
		return false
	}
	for _, proc := range accountProcedures {
		if strings.HasSuffix(req.URL.Path, proc) {
			return true
		}
	}
	return false
}

// rampTargetsOf is the whole set of paths this client signs as RAMP that the
// transport's own prefix rule does not already claim: the Broker's relay route,
// and an account RPC behind an endpoint's path prefix.
func rampTargetsOf(relayURL string) func(*http.Request) bool {
	relay := relayTargetOf(relayURL)
	return func(req *http.Request) bool {
		return relay(req) || accountTargetOf(req)
	}
}

// signAcceptances fills in each item's detached AgentAcceptance, signed with priv
// over that item's offer + the request's shared requester + the shared
// idempotency_key (the Core Invariant: the Broker forwards each item byte-
// identical, so every acceptance still verifies at whichever Exchange the item
// fans out to). An item whose offer is unsigned is refused here rather than sent:
// an acceptance floating free of a concrete offer is meaningless.
// The request is CLONED before the acceptances are written, so the message the
// caller built stays untouched: it crossed a package boundary as an argument,
// not as a buffer to fill in, and a caller that reuses or re-reads it after the
// call should see what it constructed.
func signAcceptances(
	req *rampv1.TransactionRequest, priv ed25519.PrivateKey,
) (*rampv1.TransactionRequest, error) {
	signed, ok := proto.Clone(req).(*rampv1.TransactionRequest)
	if !ok {
		return nil, &Error{
			Kind: KindMalformed, Op: "execute",
			Err: errors.New("cloned TransactionRequest has the wrong type"),
		}
	}
	for i, item := range signed.GetItems() {
		if item.GetOffer().GetSignature() == "" {
			return nil, &Error{Kind: KindMalformed, Op: "execute", Err: fmt.Errorf(
				"item %d has an unsigned offer, cannot accept it", i,
			)}
		}
		sig, err := helpers.SignOfferAcceptance(
			priv, item.GetOffer(), signed.GetRequester(), signed.GetIdempotencyKey(),
		)
		if err != nil {
			return nil, &Error{Kind: KindMalformed, Op: "execute", Err: fmt.Errorf(
				"sign acceptance for item %d: %w", i, err,
			)}
		}
		item.AgentAcceptance = &rampv1.AgentAcceptance{
			Signature:          sig,
			SignatureAlgorithm: helpers.AcceptanceSignatureAlgorithm,
		}
	}
	requestAcceptance, err := helpers.SignRequestAcceptance(priv, signed)
	if err != nil {
		return nil, &Error{Kind: KindMalformed, Op: "execute", Err: fmt.Errorf(
			"sign request acceptance: %w", err,
		)}
	}
	signed.AgentRequestAcceptance = requestAcceptance
	return signed, nil
}

// postRelay serializes req once, POSTs the exact bytes to the relay (the signing
// transport signs sig1 over them), and parses the response. The body is
// marshaled a single time so the bytes sig1 covers are the bytes on the wire.
func (c *Client) postRelay(
	ctx context.Context, req *rampv1.TransactionRequest,
) (*rampv1.TransactionResponse, error) {
	body, err := relayRequestJSON.Marshal(req)
	if err != nil {
		return nil, &Error{
			Kind: KindMalformed, Op: "execute",
			Err: fmt.Errorf("marshal TransactionRequest: %w", err),
		}
	}
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, c.relayURL, bytes.NewReader(body))
	if err != nil {
		return nil, &Error{
			Kind: KindMalformed, Op: "execute",
			Err: fmt.Errorf("build relay request: %w", err),
		}
	}
	httpReq.Header.Set("Content-Type", "application/json")
	// The correlation id is outside the covered set, so it does not affect sig1,
	// and the Broker echoes it back for log correlation. It is threaded from the
	// inbound request when there is one, so a tool call and the RAMP calls it
	// causes share an id; a fresh id is minted only when this call has no inbound
	// request behind it.
	httpReq.Header.Set(reqctx.HeaderRequestID, reqctx.IDOrNew(ctx))
	resp, err := c.relayHTTP.Do(httpReq)
	if err != nil {
		return nil, &Error{
			Kind: KindUnreachable, Op: "execute",
			Err: fmt.Errorf("relay unreachable: %w", err),
		}
	}
	defer func() { _ = resp.Body.Close() }()
	return parseRelayResponse(resp)
}

// parseRelayResponse turns the relay's HTTP reply into a TransactionResponse or a
// typed error. On success the Broker writes a protojson TransactionResponse; on
// failure it writes a protojson ErrorDetail with a non-2xx status, so a refusal
// surfaces with its typed reason rather than a bare status.
func parseRelayResponse(resp *http.Response) (*rampv1.TransactionResponse, error) {
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxRelayResponseBytes))
	if err != nil {
		return nil, &Error{
			Kind: KindMalformed, Op: "execute relay",
			Err: fmt.Errorf("read relay response: %w", err),
		}
	}
	if resp.StatusCode/100 != 2 {
		return nil, relayError(resp.StatusCode, raw)
	}
	var out rampv1.TransactionResponse
	if err = protojson.Unmarshal(raw, &out); err != nil {
		return nil, &Error{
			Kind: KindMalformed, Op: "execute relay",
			Err: fmt.Errorf("decode TransactionResponse: %w", err),
		}
	}
	return &out, nil
}

// relayError turns a non-2xx relay reply into a typed *Error. The Broker's error
// body is a protojson ErrorDetail; when it decodes it is carried through as a
// VALUE rather than rendered here, so the transport layer can surface the typed
// reason to the agent instead of the agent having to substring-match a sentence.
func relayError(status int, body []byte) error {
	e := &Error{Kind: KindRefused, Op: "execute relay", Status: status}
	var detail rampv1.ErrorDetail
	// DiscardUnknown so a Broker running a newer protocol than the one pinned
	// here still yields its typed reason rather than degrading to a bare status.
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(body, &detail); err == nil {
		if rampreason.Name(&detail) != "" || detail.GetMessage() != "" {
			e.Detail = &detail
		}
	}
	return e
}
