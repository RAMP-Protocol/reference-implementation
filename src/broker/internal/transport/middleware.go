package transport

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/broker"
)

type ctxKey string

const (
	requestIDKey ctxKey = "request_id"
)

// RequestIDMiddleware assigns or propagates an X-Request-ID per request.
func RequestIDMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		id := r.Header.Get("X-Request-ID")
		if id == "" {
			id = uuid.NewString()
		}
		w.Header().Set("X-Request-ID", id)
		ctx := context.WithValue(r.Context(), requestIDKey, id)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func requestIDFrom(ctx context.Context) string {
	if v, ok := ctx.Value(requestIDKey).(string); ok {
		return v
	}
	return "req-" + uuid.NewString()
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(body)
}

func writeError(w http.ResponseWriter, requestID string, err error) {
	var be *broker.Error
	if !errors.As(err, &be) {
		be = broker.Wrapf(broker.KindInternal, err, "")
	}
	status := statusFromKind(be.Kind)
	writeJSON(w, status, ResolveResponse{
		RequestID: requestID,
		Error:     fmt.Sprintf("%s: %s", be.Kind, be.Message),
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
