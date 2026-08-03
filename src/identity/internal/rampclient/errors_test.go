package rampclient

import (
	"errors"
	"net/http"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// relayError is pure logic over (status, body) with three outcomes, and it is the
// only place a relay refusal is classified. The MCP integration suite drives just
// the typed arm, because that is the only one a cooperating Broker double
// produces; the other two are reachable in production from any peer that answers
// with a message-only detail or a body that is not an ErrorDetail at all.
func TestRelayError_ClassifiesEachReplyShape(t *testing.T) {
	detailWithReason, err := protojson.Marshal(&rampv1.ErrorDetail{
		Message: "the offer expired",
		Reason: &rampv1.ErrorDetail_TransactionDenial{
			TransactionDenial: &rampv1.TransactionDenial{
				Reason: rampv1.DenialReason_DENIAL_REASON_OFFER_EXPIRED,
			},
		},
	})
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}
	messageOnly, err := protojson.Marshal(&rampv1.ErrorDetail{Message: "try again later"})
	if err != nil {
		t.Fatalf("marshal detail: %v", err)
	}

	tests := []struct {
		name       string
		status     int
		body       []byte
		wantReason string
		wantIn     []string
	}{
		{
			name:       "typed reason is preserved as a value",
			status:     http.StatusForbidden,
			body:       detailWithReason,
			wantReason: "DENIAL_REASON_OFFER_EXPIRED",
			wantIn:     []string{"DENIAL_REASON_OFFER_EXPIRED", "the offer expired"},
		},
		{
			name:   "a detail with only a message keeps the message and names the status",
			status: http.StatusServiceUnavailable,
			body:   messageOnly,
			wantIn: []string{"503", "Service Unavailable", "try again later"},
		},
		{
			name:   "a body that is not an ErrorDetail falls back to the status",
			status: http.StatusBadGateway,
			body:   []byte("<html>gateway blew up</html>"),
			// Both the code and the phrase: the code is what a reader greps for,
			// the phrase is what they understand.
			wantIn: []string{"502", "Bad Gateway"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := relayError(tc.status, tc.body)

			var typed *Error
			if !errors.As(err, &typed) {
				t.Fatalf("relayError returned %T, want a *rampclient.Error the caller can branch on", err)
			}
			if typed.Kind != KindRefused {
				t.Errorf("Kind = %v, want KindRefused", typed.Kind)
			}
			if typed.Status != tc.status {
				t.Errorf("Status = %d, want %d", typed.Status, tc.status)
			}
			if got := typed.Reason(); got != tc.wantReason {
				t.Errorf("Reason() = %q, want %q", got, tc.wantReason)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("message %q, want it to contain %q", err.Error(), want)
				}
			}
			// Every error this package originates says so, so a message read in
			// isolation still names where it came from.
			if !strings.HasPrefix(err.Error(), "rampclient: ") {
				t.Errorf("message %q, want the rampclient: prefix", err.Error())
			}
		})
	}
}

// A non-standard status has no StatusText, and the renderer must still produce a
// usable message rather than a dangling "(HTTP )".
func TestRelayError_UnknownStatusStillRenders(t *testing.T) {
	err := relayError(599, nil)
	if got := err.Error(); !strings.Contains(got, "599") {
		t.Errorf("message %q, want it to carry the numeric status", got)
	}
}
