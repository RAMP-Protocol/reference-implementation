package service

import (
	"errors"
	"strings"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	protobuf "google.golang.org/protobuf/proto"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
)

func TestSelectFinalizedBatchResponse(t *testing.T) {
	local := &rampv1.TransactionResponse{Ver: helpers.ProtocolVersion, AgentIdentityHash: "local"}
	winner := &rampv1.TransactionResponse{Ver: helpers.ProtocolVersion, AgentIdentityHash: "stored-winner"}
	winnerBytes, err := protobuf.Marshal(winner)
	if err != nil {
		t.Fatalf("marshal winner: %v", err)
	}
	boom := errors.New("boom")

	tests := []struct {
		name        string
		won         bool
		stored      []byte
		finalizeErr error
		readErr     error
		want        *rampv1.TransactionResponse
		wantMessage string
		wantCause   error
	}{
		{name: "local finalizer won", won: true, want: local},
		{name: "concurrent finalizer won", stored: winnerBytes, want: winner},
		{name: "finalize failed", finalizeErr: boom, wantMessage: "finalize request response", wantCause: boom},
		{name: "winner read failed", readErr: boom, wantMessage: "read winning finalized response", wantCause: boom},
		{name: "winner missing", wantMessage: "finalized response unavailable after lost finalization"},
		{name: "winner corrupt", stored: []byte{0xff, 0xff}, wantMessage: "decode winning finalized response"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := selectFinalizedBatchResponse(local, tt.won, tt.stored, tt.finalizeErr, tt.readErr)
			if tt.want != nil {
				if err != nil {
					t.Fatalf("select: %v", err)
				}
				if !protobuf.Equal(got, tt.want) {
					t.Fatalf("response = %v, want %v", got, tt.want)
				}
				return
			}
			if err == nil {
				t.Fatal("select succeeded; want Internal")
			}
			var domainErr *exchange.Error
			if !errors.As(err, &domainErr) || domainErr.Kind != exchange.KindInternal {
				t.Fatalf("error = %v, want KindInternal", err)
			}
			if !strings.Contains(err.Error(), tt.wantMessage) {
				t.Errorf("error = %q, want message containing %q", err, tt.wantMessage)
			}
			if tt.wantCause != nil && !errors.Is(err, tt.wantCause) {
				t.Errorf("error does not wrap cause %v: %v", tt.wantCause, err)
			}
		})
	}
}
