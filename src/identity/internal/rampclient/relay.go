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

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
)

// relayExecutePath is the Broker's execute-relay route. It is NOT a Connect
// /ramp.* path: the agent posts a TransactionRequest here and the Broker
// re-packages it per exchange. The one RAMP call this package makes by hand.
const relayExecutePath = "/broker/v1/exchange/execute"

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
	return signed, nil
}

// postRelay serializes req once, POSTs the exact bytes to the relay (the signing
// transport signs sig1 over them), and parses the response. The body is
// marshaled a single time so the bytes sig1 covers are the bytes on the wire.
func (c *Client) postRelay(
	ctx context.Context, req *rampv1.TransactionRequest,
) (*rampv1.TransactionResponse, error) {
	body, err := protojson.Marshal(req)
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
	resp, err := c.http.Do(httpReq)
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
		if ReasonName(&detail) != "" || detail.GetMessage() != "" {
			e.Detail = &detail
		}
	}
	return e
}
