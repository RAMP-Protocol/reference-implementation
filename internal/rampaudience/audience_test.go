package rampaudience_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1/rampadminv1connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience"
	audiencetest "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience/testutil"
)

// self is the Exchange identity every case here is checked against.
const self = "exchange.example"

// TestNewInterceptor_RefusesAnIdentityThatIsNotABareDomain pins the boot-time
// half of the contract. Each value below is a shape an operator plausibly
// reaches for, and every one of them would make the service refuse honest
// callers, so the process must not start with any of them.
func TestNewInterceptor_RefusesAnIdentityThatIsNotABareDomain(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{
		"",
		"https://exchange.example",
		"exchange.example/ramp",
		"exchange.example:99999",
		":8081",
	} {
		if _, err := rampaudience.NewInterceptor(bad); err == nil {
			t.Errorf("NewInterceptor(%q) built an interceptor; want a refusal", bad)
		}
	}
	if _, err := rampaudience.NewInterceptor("exchange.example:8081"); err != nil {
		t.Errorf("NewInterceptor with a host:port identity: %v", err)
	}
}

// TestWrapUnary_Verdicts drives one arriving request per verdict through the
// interceptor and asserts both halves of the answer: the code the peer gets,
// and whether the handler ran at all. The second half is the one that matters —
// a rejection that still reached the handler would have touched the database
// before deciding the request was not ours.
func TestWrapUnary_Verdicts(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name        string
		msg         proto.Message
		wantCode    connect.Code
		wantInMsg   string
		wantHandler bool
	}{
		{
			name:        "names this Exchange",
			msg:         &rampv1.UsageReport{Ver: helpers.ProtocolVersion, Exchange: self},
			wantHandler: true,
		},
		{
			name:        "names this Exchange with the default port spelled out",
			msg:         &rampv1.UsageReport{Ver: helpers.ProtocolVersion, Exchange: self + ":443"},
			wantHandler: true,
		},
		{
			name:      "names another Exchange",
			msg:       &rampv1.UsageReport{Ver: helpers.ProtocolVersion, Exchange: "other.example"},
			wantCode:  connect.CodeInvalidArgument,
			wantInMsg: "different Exchange",
		},
		{
			name:      "names a subdomain of this Exchange",
			msg:       &rampv1.UsageReport{Ver: helpers.ProtocolVersion, Exchange: "eu." + self},
			wantCode:  connect.CodeInvalidArgument,
			wantInMsg: "different Exchange",
		},
		{
			name:      "names nobody",
			msg:       &rampv1.UsageReport{Ver: helpers.ProtocolVersion},
			wantCode:  connect.CodeInvalidArgument,
			wantInMsg: "names no recipient",
		},
		{
			name:      "names a URL instead of a domain",
			msg:       &rampv1.UsageReport{Ver: helpers.ProtocolVersion, Exchange: "https://" + self},
			wantCode:  connect.CodeInvalidArgument,
			wantInMsg: "not a bare domain",
		},
		{
			name: "every transaction item names this Exchange",
			msg: &rampv1.TransactionRequest{Ver: helpers.ProtocolVersion, Items: []*rampv1.TransactionItem{
				{Offer: &rampv1.Offer{Exchange: self}},
				{Offer: &rampv1.Offer{Exchange: self}},
			}},
			wantHandler: true,
		},
		{
			name: "one transaction item names another Exchange",
			msg: &rampv1.TransactionRequest{Ver: helpers.ProtocolVersion, Items: []*rampv1.TransactionItem{
				{Offer: &rampv1.Offer{Exchange: self}},
				{Offer: &rampv1.Offer{Exchange: "other.example"}},
			}},
			wantCode:  connect.CodeInvalidArgument,
			wantInMsg: "different Exchange",
		},
		{
			name: "one transaction item names nobody",
			msg: &rampv1.TransactionRequest{Ver: helpers.ProtocolVersion, Items: []*rampv1.TransactionItem{
				{Offer: &rampv1.Offer{Exchange: self}},
				{Offer: &rampv1.Offer{}},
			}},
			wantCode:  connect.CodeInvalidArgument,
			wantInMsg: "names no recipient",
		},
		{
			name:      "a transaction request with no items at all",
			msg:       &rampv1.TransactionRequest{Ver: helpers.ProtocolVersion},
			wantCode:  connect.CodeInvalidArgument,
			wantInMsg: "names no recipient",
		},
		{
			// One direct hop, agent to Broker, and it terminates there. The
			// message carries no recipient field, so there is nothing to compare
			// — not a comparison that passes, and not a hop the signature binds
			// to one Broker.
			name:        "a discovery request states no recipient and is not refused",
			msg:         &rampv1.DiscoveryRequest{Ver: helpers.ProtocolVersion},
			wantHandler: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			handlerRan := false
			next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
				handlerRan = true
				return connect.NewResponse(&emptyResponse{}), nil
			}
			i := audiencetest.MustInterceptor(t, self)
			_, err := i.WrapUnary(next)(context.Background(), serverRequest(tc.msg))

			if handlerRan != tc.wantHandler {
				t.Errorf("handler ran = %v, want %v", handlerRan, tc.wantHandler)
			}
			if tc.wantHandler {
				if err != nil {
					t.Fatalf("accepted request returned %v", err)
				}
				return
			}
			var ce *connect.Error
			if !errors.As(err, &ce) {
				t.Fatalf("err = %v, want a *connect.Error", err)
			}
			if ce.Code() != tc.wantCode {
				t.Errorf("code = %v, want %v", ce.Code(), tc.wantCode)
			}
			if !strings.Contains(ce.Message(), tc.wantInMsg) {
				t.Errorf("message %q does not contain %q", ce.Message(), tc.wantInMsg)
			}
		})
	}
}

// TestWrapUnary_LeavesAClientCallAlone pins that only a server checks a
// recipient. The same interceptor type satisfies the client side of the
// interface, and a client-side check would refuse this service's own outbound
// calls — every one of which names somebody OTHER than itself.
func TestWrapUnary_LeavesAClientCallAlone(t *testing.T) {
	t.Parallel()
	i := audiencetest.MustInterceptor(t, self)
	called := false
	next := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		called = true
		return connect.NewResponse(&emptyResponse{}), nil
	}
	req := clientRequest(&rampv1.UsageReport{Ver: helpers.ProtocolVersion, Exchange: "other.example"})
	if _, err := i.WrapUnary(next)(context.Background(), req); err != nil {
		t.Fatalf("a client call naming its peer was refused: %v", err)
	}
	if !called {
		t.Error("the client call did not reach the next hop")
	}
}

// TestEveryServedRequestIsChecked is the coverage guard.
//
// It walks every method the two RAMP services this repository serves declare,
// and asserts two things about each: that it is unary, because a streaming RPC
// would reach a passthrough that checks nothing; and that its request message is
// either addressed — the interceptor finds a recipient in it — or named in the
// exception list below with the reason it carries none. A new RPC therefore
// cannot arrive unguarded: it either has the field and is checked, or this test
// fails until somebody writes down why it does not.
//
// The exceptions come from the protocol, not from this repository's
// convenience, and each is the proto's own documented reasoning.
func TestEveryServedRequestIsChecked(t *testing.T) {
	t.Parallel()
	notAddressed := map[protoreflect.FullName]string{
		// One direct hop that terminates at the Broker. The Broker authors
		// fresh per-Exchange queries from it and THOSE carry the field; the
		// agent could not name the recipients in any case, because choosing the
		// fan-out set is the Broker's job.
		"ramp.v1.DiscoveryRequest": "one direct hop, agent to Broker",
		// The admin plane is not a RAMP peer surface: it has no signer, is
		// reached only from an allowlisted network, and its messages name a
		// tenant rather than an Exchange. It is walked anyway so that the day one
		// of them gains a recipient, it is checked rather than exempt by
		// oversight.
		"ramp.admin.v1.SetTenantFeeRateRequest":   "admin plane, names a tenant not an Exchange",
		"ramp.admin.v1.SetReportingPolicyRequest": "admin plane, names a tenant not an Exchange",
	}
	// EVERY service the interceptor is mounted on, not just the two that carry
	// addressed requests today. Listing only those would let the exception entry
	// below be deleted with the test still passing, because the message it
	// excuses is the input of a method on a service the walk never reached.
	for _, svcName := range []protoreflect.FullName{
		rampv1connect.ExchangeServiceName,
		rampv1connect.CatalogServiceName,
		rampv1connect.BrokerServiceName,
		rampadminv1connect.AdminServiceName,
	} {
		desc, err := protoregistry.GlobalFiles.FindDescriptorByName(svcName)
		if err != nil {
			t.Fatalf("find service %s: %v", svcName, err)
		}
		svc, ok := desc.(protoreflect.ServiceDescriptor)
		if !ok {
			t.Fatalf("%s is not a service descriptor", svcName)
		}
		methods := svc.Methods()
		for i := range methods.Len() {
			method := methods.Get(i)
			// A streaming request would reach WrapStreamingHandler, which does not
			// check a recipient. Pinning that every served method is unary is what
			// makes that passthrough safe, instead of a comment claiming it is.
			if method.IsStreamingClient() || method.IsStreamingServer() {
				t.Errorf("%s.%s streams; the recipient check only covers unary RPCs",
					svcName, method.Name())
				continue
			}
			input := method.Input()
			msg, err := protoregistry.GlobalTypes.FindMessageByName(input.FullName())
			if err != nil {
				t.Fatalf("find message %s: %v", input.FullName(), err)
			}
			_, addressed := rampaudience.Recipients(msg.New().Interface())
			reason, excused := notAddressed[input.FullName()]
			switch {
			case addressed && excused:
				t.Errorf("%s.%s: %s carries a recipient after all — drop the exception (%q)",
					svcName, method.Name(), input.FullName(), reason)
			case !addressed && !excused:
				t.Errorf("%s.%s: %s states no recipient and is not in the exception list — "+
					"it reaches the handler unchecked",
					svcName, method.Name(), input.FullName())
			}
		}
	}
}

// serverRequest and clientRequest build the two shapes an interceptor sees. The
// side is carried on the Spec, and it is what decides whether a recipient is
// checked at all, so a test cannot leave it to a zero value: connect.NewRequest
// on its own yields IsClient false, which is to say a SERVER request, and the
// passthrough case would then assert the opposite of what it claims.
func serverRequest(msg proto.Message) connect.AnyRequest {
	return &fakeRequest{msg: msg, isClient: false}
}

func clientRequest(msg proto.Message) connect.AnyRequest {
	return &fakeRequest{msg: msg, isClient: true}
}

type fakeRequest struct {
	connect.AnyRequest
	msg      proto.Message
	isClient bool
}

func (r *fakeRequest) Any() any { return r.msg }

func (r *fakeRequest) Spec() connect.Spec {
	return connect.Spec{IsClient: r.isClient, Procedure: "/ramp.v1.ExchangeService/Test"}
}

// emptyResponse stands in for whatever the handler would have returned; no case
// here reads it.
type emptyResponse = rampv1.UsageReportResponse
