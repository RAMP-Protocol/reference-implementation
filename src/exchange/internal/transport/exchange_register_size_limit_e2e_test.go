//go:build integration

package transport_test

import (
	"fmt"
	"math"
	"strconv"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampconnect "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1/rampv1connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig/transportconnect"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// This file covers the Register RPC's size limits: the coarse request cap the
// ExchangeService mount pins through connectserver.WithMaxRequestBytes — one
// number bounding both the raw body and the decompressed message — and the
// tighter, semantic bounds on registration_data at the gate. Kept separate from
// exchange_register_e2e_test.go (the core registration flow) and
// exchange_register_gates_e2e_test.go (the published schema and terms digest) so
// each file stays a single scenario.
//
// The bounds are the SDK's, not this Exchange's: 64 top-level members, 32 nested
// containers, and 16384 bytes of RFC 8785 canonical JSON. The agent pre-checks
// with the same call on the same decoded object, so both ends reach the same
// verdict on the same payload. Each case below is built from the SDK's own
// constant rather than a copy of the number, so a protocol revision that moves a
// bound moves these payloads with it.

// TestExchangeRegister_RegistrationDataBounds drives each bound through the real
// router. Every case asserts the same three things: the transport code, the
// ABSENCE of a registration_failure reason, and the absence of every side effect.
//
// The absent reason is the load-bearing one. A bounds violation is a malformed
// request, not non-conformance to a published schema, so it must NOT carry
// INVALID_REGISTRATION_DATA — that reason names a schema failure and applies only
// when a schema is published. These harnesses publish none at all, so a reason
// appearing here would mean the gate classified a malformed request as a schema
// failure.
func TestExchangeRegister_RegistrationDataBounds(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]any
		// wants is the number the refusal must name. Without it a payload that
		// stopped crossing its own bound and started crossing a different one
		// would still be refused with InvalidArgument and no reason, so every
		// assertion below would hold while the case name lied and the bound it
		// claims to cover quietly lost its only test here. The three numbers
		// share no substring, so the check cannot match the wrong one.
		wants int
	}{
		{"over the canonical byte budget", testutil.RegistrationOverByteCap(), helpers.MaxRegistrationDataBytes},
		{"over the top-level member budget", testutil.RegistrationOverMemberCap(), helpers.MaxRegistrationDataMembers},
		{"nested past the depth budget", testutil.RegistrationOverDepthCap(), helpers.MaxRegistrationDataDepth},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			a := h.newAgent(t, "bounds.example")

			_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(
				testutil.RegistrationStruct(t, tc.payload),
			)))
			if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
			}
			if want := strconv.Itoa(tc.wants); !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not name the bound this case covers (%s)", err, want)
			}
			assertNoRegistrationFailureReason(t, err)
			assertNoRegistrationSideEffects(t, h, a)
		})
	}
}

// assertNoRegistrationFailureReason checks that a refusal carries the shared
// reasonless fault envelope: an ErrorDetail with the exchange Domain stamped, and
// no registration_failure oneof.
func assertNoRegistrationFailureReason(t *testing.T, err error) {
	t.Helper()
	detail := testutil.SingleErrorDetail(t, err)
	if failure := detail.GetRegistrationFailure(); failure != nil {
		t.Errorf("a bounds violation carries registration_failure %v; it is a malformed "+
			"request, and INVALID_REGISTRATION_DATA names a schema failure instead", failure)
	}
	assertExchangeDomain(t, detail)
}

// TestExchangeRegister_BodyOverReadCapIsRefusedBeforeVerification proves the
// RAW-body bound on the ExchangeService mount, the coarse outer wall behind the
// semantic registration_data bounds above. The SDK's verify face buffers the
// whole body to check an RFC 9421 signature over the exact bytes, and it does
// that before it knows who is calling, so the bound has to bite before
// verification — which is why the request is UNSIGNED and sent raw, bypassing
// the Connect client: the caller the bound exists for never authenticates, and
// a gRPC client would report the 413 as CodeUnknown.
//
// Two requests, because either alone proves too little. An over-cap body must
// be refused as a resource limit — 413, resource_exhausted, correlated by
// X-Request-ID — and never as Unauthenticated; an unsigned request is refused
// anyway, so a status check alone would pass with no bound at all. An
// under-cap unsigned body must get PAST the size gate and be refused by
// verification (401), proving the bound is not refusing everything. The
// overshoot past the cap is small on purpose: the server refuses as soon as the
// cap is crossed and discards what remains before answering, and a request
// with megabytes still unsent would meet a closed connection instead of the 413.
func TestExchangeRegister_BodyOverReadCapIsRefusedBeforeVerification(t *testing.T) {
	h := newRegisterHarness(t)
	url := h.server + rampconnect.ExchangeServiceRegisterProcedure

	assertRefusedTooLarge(t, postRawConnect(t, h.baseTransport, url,
		padJSON([]byte("{}"), transport.MaxRPCReadBytes+bodyCapOvershoot)))
	assertReachedVerification(t, postRawConnect(t, h.baseTransport, url, padJSON([]byte("{}"), 128)))
}

// TestExchangeRegister_BodyOverReadCapAuditsAsASizeRefusal covers the half the
// response code cannot show: what the server WROTE DOWN about the refusal.
//
// The raw-body bound sits inside the SDK's verify face, so an over-cap read
// fails there and travels to the reject observer this Exchange registers. The
// observer classifies through the SDK's own reject reasons, and that enum names
// the four authentication outcomes only — a body past the cap is none of them,
// so it took the default and every such refusal was audited as a signature
// failure. An operator filtering the reject log for a key or clock problem
// would find a caller that simply sent too much, and the caller that did have a
// signature problem is now indistinguishable from it.
//
// Both halves are asserted together. The size refusal must carry the size
// outcome, and an ordinary bad signature must still carry the signature one —
// without the second, a classifier that answered "body_too_large" for
// everything would pass.
func TestExchangeRegister_BodyOverReadCapAuditsAsASizeRefusal(t *testing.T) {
	logs := &safeBuffer{}
	h := newRegisterHarnessWith(t, registerHarnessOptions{
		billing: billing.NewInMemoryAdapter(billing.InMemoryOptions{}),
		logs:    logs,
	})
	url := h.server + rampconnect.ExchangeServiceRegisterProcedure

	assertRefusedTooLarge(t, postRawConnect(t, h.baseTransport, url,
		padJSON([]byte("{}"), transport.MaxRPCReadBytes+bodyCapOvershoot)))
	assertRejectOutcome(t, logs.String(), transportconnect.OutcomeBodyTooLarge)

	// Drop the first request's record before driving the second. Both write a
	// reject line under the same message key, and assertRejectOutcome reads the
	// FIRST one it finds, so without this the signature assertion would be
	// answered by the size refusal above.
	logs.Reset()
	assertReachedVerification(t, postRawConnect(t, h.baseTransport, url, padJSON([]byte("{}"), 128)))
	assertRejectOutcome(t, logs.String(), "signature")
}

// TestExchangeRegister_MessageOverReadCapIsResourceExhausted proves the second
// quantity the cap bounds: the DECOMPRESSED message. Connect decompresses every
// request before decoding it and the wire rules do not bound that work, so the
// bound is on the inflated size. The client sends gzip: the raw body stays a
// few kilobytes, well under the raw-body bound the test above covers, while
// the message it inflates to crosses MaxRPCReadBytes. The request is signed and
// clears verification; the handler's decode refuses it as ResourceExhausted,
// before self-signup or the registration_data gate runs.
//
// The side effect asserted absent is the account. GetAccountStatus, the public
// read surface, resolves the caller the way Register does — lazily registering
// the directory identity — and answers NotFound for an identity with no
// billing_ref, so the probe cannot itself produce the outcome it checks for.
// The fuller check the bounds test uses does not apply here: it reads the
// agent's row through the repository, and a request refused before the handler
// never created one.
//
// Only the gzip client sends. The plain client the fixture built for the same
// key stays unused, so the two cannot collide in the replay store.
func TestExchangeRegister_MessageOverReadCapIsResourceExhausted(t *testing.T) {
	h := newRegisterHarness(t)
	a := h.newAgent(t, "overcap.example")
	gz := h.clientWith(a.id, a.priv, connect.WithSendGzip())

	huge := strings.Repeat("x", transport.MaxRPCReadBytes+bodyCapOvershoot)
	_, err := gz.Register(h.ctx, connect.NewRequest(newRegisterRequest(
		testutil.RegistrationStruct(t, map[string]any{"blob": huge}),
	)))
	if got := connect.CodeOf(err); got != connect.CodeResourceExhausted {
		t.Fatalf("code = %v, want ResourceExhausted (err=%v)", got, err)
	}
	_, err = gz.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Fatalf("GetAccountStatus after the refused Register = %v, want NotFound "+
			"(a refusal must leave no account) (err=%v)", got, err)
	}
}

// TestExchangeRegister_PayloadWithNoJSONFormIsRefused drives every value JSON
// cannot write down through the real router. Each is refused as a malformed
// request, because RFC 8785 has no encoding for it: the payload has no canonical
// form, so the byte bound has nothing to measure and the protocol's bounds
// cannot be applied to it.
//
// The class has TWO members, and both cross the wire intact. A non-finite number
// is one: Struct's number_value is an IEEE-754 double, so NaN and the infinities
// travel unchanged, and structpb.NewValue does not reject one, so an ordinary Go
// client reaches this without touching raw proto. A Value with NO member of its
// kind oneof set is the other: a oneof with nothing set is well-formed on the
// wire, the binary decoder accepts it, and proto-JSON refuses to render it.
//
// Both are easy to lose, because neither survives a conversion to a Go map. AsMap
// renders a non-finite double as the string "NaN", "Infinity" or "-Infinity",
// which a payload may legitimately carry, and renders an unset kind as nil, which
// is what a real JSON null gives. A check written against the converted payload
// sees a well-formed value in both cases and accepts it — which is a Go Exchange
// storing the text "NaN" where the caller sent a number, and two conformant
// implementations answering the same signed request differently, since Python and
// TypeScript decode into objects that keep the real value.
//
// Every container the locator descends is covered, because each one converts by
// that same rule and a container with no case is a container it can stop
// descending without anything noticing: an object member, a list element, and an
// object nested inside a list.
//
// Each case also pins the MEMBER PATH the refusal names. The path is the only
// part of the message that tells the caller where the bad value is, and it is
// built by composition — every level prepends its own key or index to the suffix
// the level below returned — so a level that drops the suffix, or numbers an
// index wrongly, still refuses the payload and still passes a test that reads
// only the code. Every payload here holds exactly one offending value, so the
// path is deterministic; with two, the locator names one of them and Go's map
// iteration order decides which.
//
// The refusal must also NOT name the byte cap. That bound is defined as the
// length of the canonical encoding, and these payloads have no encoding, so
// reporting a number would state a measurement nobody took.
func TestExchangeRegister_PayloadWithNoJSONFormIsRefused(t *testing.T) {
	// untyped is a Value with no member of its kind oneof set. It cannot be
	// spelled through structpb.NewValue, which has no argument that produces one,
	// so every case carrying it is assembled field by field.
	untyped := func() *structpb.Value { return &structpb.Value{} }
	structOf := func(fields map[string]*structpb.Value) *structpb.Struct {
		return &structpb.Struct{Fields: fields}
	}
	cases := []struct {
		name     string
		payload  func(t *testing.T) *structpb.Struct
		wantPath string
	}{
		{"NaN", fromMap(map[string]any{"vat_id": math.NaN()}), "vat_id"},
		{"positive infinity", fromMap(map[string]any{"vat_id": math.Inf(1)}), "vat_id"},
		{"negative infinity", fromMap(map[string]any{"vat_id": math.Inf(-1)}), "vat_id"},
		{
			"inside an object",
			fromMap(map[string]any{"address": map[string]any{"lat": math.NaN()}}),
			"address.lat",
		},
		{
			// Two objects deep, so the OUTER object arm has a non-empty suffix to
			// prepend to. One level deep the suffix is always empty and an arm
			// that dropped it would still build the right path.
			"two objects deep",
			fromMap(map[string]any{"billing": map[string]any{"address": map[string]any{"lat": math.NaN()}}}),
			"billing.address.lat",
		},
		{
			"inside a list",
			fromMap(map[string]any{"coords": []any{1.0, math.NaN()}}),
			"coords[1]",
		},
		{
			"inside an object inside a list",
			fromMap(map[string]any{"regions": []any{map[string]any{"lat": math.NaN()}}}),
			"regions[0].lat",
		},
		{
			"a value with no type set",
			func(*testing.T) *structpb.Struct {
				return structOf(map[string]*structpb.Value{"vat_id": untyped()})
			},
			"vat_id",
		},
		{
			"a value with no type set inside an object",
			func(*testing.T) *structpb.Struct {
				return structOf(map[string]*structpb.Value{
					"address": structpb.NewStructValue(structOf(
						map[string]*structpb.Value{"lat": untyped()},
					)),
				})
			},
			"address.lat",
		},
		{
			"a value with no type set inside a list",
			func(*testing.T) *structpb.Struct {
				return structOf(map[string]*structpb.Value{
					"coords": structpb.NewListValue(&structpb.ListValue{Values: []*structpb.Value{
						structpb.NewNumberValue(1), untyped(),
					}}),
				})
			},
			"coords[1]",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newRegisterHarness(t)
			a := h.newAgent(t, "nojsonform.example")

			_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(tc.payload(t))))
			if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
				t.Fatalf("Register with %s = %v, want InvalidArgument (err=%v)", tc.name, got, err)
			}
			if want := fmt.Sprintf("member %q", tc.wantPath); !strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q does not name %s — the path is what tells the caller "+
					"which value to fix", err, want)
			}
			if !strings.Contains(err.Error(), "no JSON form") {
				t.Errorf("refusal %q does not name the class it refused", err)
			}
			if want := strconv.Itoa(helpers.MaxRegistrationDataBytes); strings.Contains(err.Error(), want) {
				t.Errorf("refusal %q reports the byte cap for a payload that has no "+
					"canonical encoding to measure", err)
			}
			assertNoRegistrationFailureReason(t, err)
			assertNoRegistrationSideEffects(t, h, a)
		})
	}
}

// fromMap adapts one of the map-shaped payloads above to the table's builder
// shape. structpb.NewStruct carries a non-finite double through unchanged, which
// is exactly the property the NaN cases rely on; it has no spelling for an unset
// kind, which is why those cases are assembled by hand instead.
func fromMap(m map[string]any) func(*testing.T) *structpb.Struct {
	return func(t *testing.T) *structpb.Struct {
		t.Helper()
		return testutil.RegistrationStruct(t, m)
	}
}
