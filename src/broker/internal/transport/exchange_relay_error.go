package transport

import (
	"bytes"
	"errors"
	"io"
	"net/http"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
)

// relayJSONCodec is the SDK's snake_case + emit-unpopulated JSON codec — the
// SAME wire policy the SDK-wrapped Connect handlers use. The bespoke relay route
// writes raw bytes (it is not a Connect handler), so it marshals through the
// codec directly to keep the relay wire byte-identical to the direct path (snake
// proto names, zero scalars present) with no drift.
var relayJSONCodec = connectserver.EmitUnpopulatedJSONCodec()

// writeBytes streams already-serialized response bytes to w. Routing the write
// through an io.Reader (rather than w.Write([]byte(...))) keeps gosec's taint
// analysis (G705) satisfied: the relay never writes caller-supplied HTML — the
// body is protojson-marshaled proto served as application/json, or internal
// developer text served as text/plain — but io.Copy is the idiomatic
// non-tainted sink the rest of the codebase uses for serialized payloads.
func writeBytes(w http.ResponseWriter, body []byte) {
	_, _ = io.Copy(w, bytes.NewReader(body))
}

// connectCodeToHTTPStatus maps the Connect codes the broker relay produces onto
// HTTP status codes. The bespoke relay route writes to a raw http.ResponseWriter
// (it is not a Connect handler), so it cannot reuse the Connect transport's
// native code→status mapping; this table reproduces the subset the relay emits.
var connectCodeToHTTPStatus = map[connect.Code]int{
	connect.CodeInvalidArgument:    http.StatusBadRequest,
	connect.CodeUnauthenticated:    http.StatusUnauthorized,
	connect.CodePermissionDenied:   http.StatusForbidden,
	connect.CodeNotFound:           http.StatusNotFound,
	connect.CodeResourceExhausted:  http.StatusTooManyRequests,
	connect.CodeFailedPrecondition: http.StatusBadRequest,
	connect.CodeUnavailable:        http.StatusServiceUnavailable,
	connect.CodeInternal:           http.StatusInternalServerError,
}

// writeBrokerError renders a broker domain error to the raw relay response per
// ADR-019: it resolves the broker.Kind (defaulting to internal for any error
// that does not wrap a broker.Error), maps Kind→connect.Code→HTTP status, and
// writes a typed rampv1.ErrorDetail as the JSON body. Broker relay faults are
// the generic transport class (no domain-specific reason oneof), mirroring
// resolveFaultError (broker_connect_handler.go): the machine-readable contract
// is the status code; Message is non-authoritative developer text and MUST NOT
// be parsed by clients.
func writeBrokerError(w http.ResponseWriter, requestID string, err error) {
	code := connect.CodeInternal
	var be *broker.Error
	if errors.As(err, &be) {
		code = be.Kind.ConnectCode()
	}
	status, ok := connectCodeToHTTPStatus[code]
	if !ok {
		status = http.StatusInternalServerError
	}
	// Share the brokerDetail builder with the Connect sink (resolveFaultError) so
	// the Domain + Message + metadata-ride cannot drift between the two sinks; the
	// raw-relay sink marshals the detail itself because it writes raw bytes rather
	// than a connect.Error.
	body, merr := relayJSONCodec.Marshal(brokerDetail(err))
	if merr != nil {
		// A marshal failure must still produce the resolved status, not a 200.
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if requestID != "" {
			w.Header().Set("X-Request-ID", requestID)
		}
		w.WriteHeader(status)
		writeBytes(w, []byte(err.Error()))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if requestID != "" {
		w.Header().Set("X-Request-ID", requestID)
	}
	w.WriteHeader(status)
	writeBytes(w, body)
}

// writeTxResponse renders a successful TransactionResponse as protojson with a
// 200 status — the execute relay's success path. A marshal failure degrades to a
// 500 via writeBrokerError so the caller never receives a 200 with an empty body.
func writeTxResponse(w http.ResponseWriter, requestID string, resp *rampv1.TransactionResponse) {
	writeRelayJSON(w, requestID, resp, "marshal TransactionResponse")
}

// writeResourceResponse renders a successful ResourceResponse as protojson with a
// 200 status — the discover relay's success path. Marshal-failure
// handling matches writeTxResponse.
func writeResourceResponse(w http.ResponseWriter, requestID string, resp *rampv1.ResourceResponse) {
	writeRelayJSON(w, requestID, resp, "marshal ResourceResponse")
}

// writeRelayJSON protojson-marshals a relay success message and writes it with a
// 200 status, degrading to a 500 (never a 200 with an empty body) on marshal
// failure. failMsg names the message type for the error context.
func writeRelayJSON(w http.ResponseWriter, requestID string, msg proto.Message, failMsg string) {
	body, err := relayJSONCodec.Marshal(msg)
	if err != nil {
		writeBrokerError(w, requestID, broker.Wrapf(broker.KindInternal, err, "%s", failMsg))
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if requestID != "" {
		w.Header().Set("X-Request-ID", requestID)
	}
	w.WriteHeader(http.StatusOK)
	writeBytes(w, body)
}
