package rampaudience_test

import (
	"context"
	"encoding/json"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"

	audiencetest "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/reqctx"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// TestWrapUnary_LogsTheRefusalWhereAnOperatorLooks pins the shape of the one
// record this side keeps of a refused request. Without it the only trace is the
// caller's, and an operator debugging "my agent gets invalid_argument" has
// nothing to read.
//
// The RPC goes under "path" because that is the key the signature gate writes
// for the same value: an operator building one view of refused requests should
// not have to know that two rejections on the same request name the field two
// ways. The verdict is the SDK's own token, so it can be filtered against the
// same vocabulary the conformance vectors record.
func TestWrapUnary_LogsTheRefusalWhereAnOperatorLooks(t *testing.T) {
	t.Parallel()
	logs, entry := refuse(t, &rampv1.UsageReport{
		Ver: helpers.ProtocolVersion, Exchange: "other.example",
	})
	if len(logs.Find("rampaudience.refused")) != 1 {
		t.Fatalf("refusal records = %d, want exactly 1", len(logs.Find("rampaudience.refused")))
	}
	for _, want := range []struct{ key, value string }{
		{"path", "/ramp.v1.ExchangeService/Test"},
		{"verdict", "mismatch"},
		{"self", self},
		{"level", "WARN"},
	} {
		if got := entry[want.key]; got != want.value {
			t.Errorf("%s = %v, want %q", want.key, got, want.value)
		}
	}
	if entry["reason"] == "" {
		t.Error("the record carries no reason, so it says nothing an operator can act on")
	}
}

// refuse drives one refused request through the interceptor with a capturing
// logger on the context, and returns the capture plus the decoded record.
func refuse(t *testing.T, msg *rampv1.UsageReport) (*testutil.LogCapture, map[string]any) {
	t.Helper()
	logs, logger := testutil.NewLogCapture()
	i := audiencetest.MustInterceptor(t, self)
	next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("the handler ran on a refused request")
		return nil, nil
	}
	ctx := reqctx.IntoContext(context.Background(), logger)
	if _, err := i.WrapUnary(next)(ctx, serverRequest(msg)); err == nil {
		t.Fatal("the request was not refused")
	}
	records := logs.Find("rampaudience.refused")
	if len(records) == 0 {
		t.Fatal("the refusal left no record")
	}
	entry := map[string]any{}
	if err := json.Unmarshal([]byte(records[0]), &entry); err != nil {
		t.Fatalf("decode record: %v", err)
	}
	return logs, entry
}

// TestWrapUnary_RefusalNamesTheFieldAndTheItem pins what a client reads off the
// refusal. The verdict alone does not tell a caller where to look: a batch of
// twenty items refused for one of them is not actionable without the position,
// and a field name in a spelling no other service uses makes the caller handle
// the same fault twice.
func TestWrapUnary_RefusalNamesTheFieldAndTheItem(t *testing.T) {
	t.Parallel()
	cases := map[string]struct {
		msg       proto.Message
		wantField string
		wantIndex string
	}{
		"a report names another Exchange": {
			msg: &rampv1.UsageReport{
				Ver: helpers.ProtocolVersion, Exchange: "other.example",
			},
			wantField: "exchange",
		},
		"the third item of a batch names another Exchange": {
			msg: &rampv1.TransactionRequest{
				Ver: helpers.ProtocolVersion,
				Items: []*rampv1.TransactionItem{
					{Offer: &rampv1.Offer{Exchange: self}},
					{Offer: &rampv1.Offer{Exchange: self}},
					{Offer: &rampv1.Offer{Exchange: "other.example"}},
				},
			},
			// The Broker's spelling for the same field on the same message, so a
			// client handles one fault rather than one per service.
			wantField: "offer.exchange",
			wantIndex: "2",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			meta := refusalMetadata(t, tc.msg)
			if got := meta["field"]; got != tc.wantField {
				t.Errorf("field = %q, want %q", got, tc.wantField)
			}
			if got := meta["item_index"]; got != tc.wantIndex {
				t.Errorf("item_index = %q, want %q", got, tc.wantIndex)
			}
		})
	}
}

// refusalMetadata drives one refused request and returns the metadata on the
// typed detail the caller receives.
func refusalMetadata(t *testing.T, msg proto.Message) map[string]string {
	t.Helper()
	i := audiencetest.MustInterceptor(t, self)
	next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		t.Fatal("the handler ran on a refused request")
		return nil, nil
	}
	_, err := i.WrapUnary(next)(context.Background(), serverRequest(msg))
	return testutil.SingleErrorDetail(t, err).GetMetadata()
}
