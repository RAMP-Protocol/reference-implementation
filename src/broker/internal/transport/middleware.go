package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig/transportconnect"
	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
)

type ctxKey string

const (
	requestIDKey ctxKey = "request_id"
)

// maxAgentBodyBytes caps the request body every agent-facing POST will buffer
// before processing. The broker's agent endpoints carry small protobuf-JSON
// payloads (a RAMPRequest / TransactionRequest is well under a kilobyte), so a
// 64 KiB ceiling never truncates a legitimate request. The cap is a DoS guard:
// without it an (intentionally pre-auth) endpoint like the ExecuteTransaction
// relay would buffer an arbitrarily large attacker body into memory before any
// signature check could reject it. Read with io.LimitReader at every agent POST.
const maxAgentBodyBytes int64 = 64 * 1024

// withRequestID stores id under the broker's request-id context key.
func withRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, requestIDKey, id)
}

// RequestIDMiddleware assigns or propagates an X-Request-ID per request and
// attaches a request-id-scoped logger to the context (reqctx.IntoContext) so
// downstream handlers log with correlation without re-passing the id, mirroring
// the Exchange. The shared body lives in reqctx; this service passes its own
// withRequestID context-key setter.
func RequestIDMiddleware(logger *slog.Logger, next http.Handler) http.Handler {
	return reqctx.RequestIDMiddleware(logger, withRequestID, next)
}

// LogHTTPSigReject is the OnError callback for the broker's global RFC 9421
// httpsig gate (wired in cmd/server). It logs the rejection through the
// request-scoped logger so the line carries the request_id RequestIDMiddleware
// stamped — these are the auth-rejection lines, the highest-value ones to
// correlate. RequestIDMiddleware is outermost, so r.Context() already carries
// the scoped logger; reqctx falls back to slog.Default() if a request ever
// bypasses the middleware. The httpsig interceptor only invokes OnError with a
// non-nil err.
func LogHTTPSigReject(r *http.Request, err error) {
	reqctx.FromContext(r.Context()).WarnContext(r.Context(), "httpsig: reject",
		"path", r.URL.Path, "outcome", transportconnect.RejectOutcome(err), "err", err.Error())
}

func requestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return "req-" + uuid.NewString()
}

// writeProtoJSON renders a proto message as canonical proto-JSON.
func writeProtoJSON(w http.ResponseWriter, status int, msg proto.Message) {
	b, err := protojson.Marshal(msg)
	if err != nil {
		// Unreachable for the RAMPResponse values this package builds; guard
		// fails closed without stamping a JSON content-type on an empty body.
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(b)
}

// writeProtoError renders a domain error as a canonical RAMPResponse: the
// request id plus the error string under ext["ramp.broker.error"], with the
// HTTP status mapped from the error kind. RAMPResponse has no canonical error
// field, so the Broker surfaces the cause under its ext namespace.
func writeProtoError(w http.ResponseWriter, requestID string, err error) {
	var be *broker.Error
	if !errors.As(err, &be) {
		be = broker.Wrapf(broker.KindInternal, err, "")
	}
	ext, _ := structpb.NewStruct(map[string]any{
		"ramp.broker.error": fmt.Sprintf("%s: %s", be.Kind, be.Message),
	})
	writeProtoJSON(w, statusFromKind(be.Kind), &rampv1.RAMPResponse{
		Ver:       rampproto.Ver,
		RequestId: requestID,
		Ext:       ext,
	})
}

func statusFromKind(k broker.Kind) int {
	switch k {
	case broker.KindInvalidArgument:
		return http.StatusBadRequest
	case broker.KindNotFound:
		return http.StatusNotFound
	case broker.KindUnauthenticated:
		return http.StatusUnauthorized
	case broker.KindPermissionDenied:
		return http.StatusForbidden
	case broker.KindBudgetExhausted:
		return http.StatusPaymentRequired
	case broker.KindUpstreamUnavailable:
		return http.StatusBadGateway
	case broker.KindUpstreamRejected:
		return http.StatusConflict
	default:
		return http.StatusInternalServerError
	}
}
