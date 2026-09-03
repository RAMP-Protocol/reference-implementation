//go:build integration

package transport_test

import (
	"math"
	"strconv"
	"strings"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// This file answers one question the per-gate tests cannot: when a single
// request breaks MORE THAN ONE gate, which refusal does the caller get?
//
// A registration is checked in a fixed sequence: top-level member count, nesting
// depth, whether the payload has a JSON form at all, its canonical byte size,
// then the terms digest, then the published schema. Every other test in this
// package sends a request that breaks exactly one gate, so the order is
// invisible to them: swap two checks and they all still pass. These cases are
// what pin it.
//
// The whole sequence is the PROTOCOL's, and each position has a stated reason.
// A check that exists to stop work precedes the work, which puts the four
// payload checks before the schema. Canonicalizability precedes the byte size
// because that size is DEFINED as the length of the canonical encoding, so a
// payload with no encoding has no length to compare and "too large" would state
// a measurement nobody took. And the terms gate precedes the schema because the
// schema may itself have moved in the revision the caller has not read yet, so
// naming its field errors would send that caller to fix the wrong thing; it also
// keeps one refusal to one remedy, since a request earning both is given the one
// that has to be done first.
//
// The first four run inside the SDK, which owns their order, so the case below
// that pins canonicalizability-before-size is checking this Exchange hands the
// payload to that face rather than measuring it itself.
//
// The last two cases run on newGateHarness, which publishes a schema AND a
// digest. The per-bound tests cannot cover those: they run on
// newRegisterHarness, which publishes no schema, so there is no second gate for
// the bounds to precede.

// TestExchangeRegister_NoJSONFormAnswersBeforeTheByteBound sends one payload
// that is over the canonical byte cap AND carries a NaN. The caller must be told
// about the value, not the size.
//
// The byte bound is defined as the length of the canonical encoding. This payload
// has no canonical encoding at all, so there is no length to compare against the
// cap, and answering "too large" would report a measurement that was never taken
// — and would send the agent to shrink a payload whose size is not the problem.
//
// It runs on newRegisterHarness, which publishes no schema: the ordering under
// test is between two payload checks, so a third gate would only add noise.
func TestExchangeRegister_NoJSONFormAnswersBeforeTheByteBound(t *testing.T) {
	h := newRegisterHarness(t)
	a := h.newAgent(t, "nojsonformfirst.example")

	// The over-byte-cap payload with one member replaced by a NaN, so it breaks
	// both checks and neither case can pass by breaking only its own.
	payload := testutil.RegistrationOverByteCap()
	payload["k00"] = math.NaN()

	_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(
		testutil.RegistrationStruct(t, payload),
	)))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
	}
	if !strings.Contains(err.Error(), "no JSON form") {
		t.Errorf("refusal %q does not name the value, so the byte bound answered first", err)
	}
	if want := strconv.Itoa(helpers.MaxRegistrationDataBytes); strings.Contains(err.Error(), want) {
		t.Errorf("refusal %q reports the byte cap (%s) for a payload that has no canonical "+
			"encoding to measure", err, want)
	}
	assertNoRegistrationFailureReason(t, err)
	assertNoRegistrationSideEffects(t, h, a)
}

// TestExchangeRegister_BoundsAnswerBeforeTheSchema sends one payload that is
// over the canonical byte cap AND missing both members the published schema
// requires. The caller must be told about the bound.
//
// The distinction matters to an agent: a bounds refusal means shrink the
// payload, a schema refusal means correct its members. An Exchange that
// validated first would spend the work the bound exists to cap, and would then
// hand back a field list for a payload the agent has to shrink anyway.
func TestExchangeRegister_BoundsAnswerBeforeTheSchema(t *testing.T) {
	h := newGateHarness(t)
	a := h.newAgent(t, "boundsfirst.example")

	// Over the byte cap, and its members are k00..k31 — so neither company_name
	// nor billing_email is present and the published schema refuses it too.
	_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, testutil.RegistrationOverByteCap()), testutil.TermsDigest,
	)))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
	}
	if want := strconv.Itoa(helpers.MaxRegistrationDataBytes); !strings.Contains(err.Error(), want) {
		t.Errorf("refusal %q does not name the byte bound (%s), so it is not the bounds "+
			"check answering", err, want)
	}
	// A reasonless envelope is the whole point: INVALID_REGISTRATION_DATA here
	// would mean the schema gate answered first.
	assertNoRegistrationFailureReason(t, err)
	assertNoRegistrationSideEffects(t, h, a)
}

// TestExchangeRegister_TermsAnswerBeforeTheSchema sends one payload carrying a
// superseded terms digest AND breaking the published schema. The caller must be
// told about the terms.
//
// The agent's remedy differs: stale terms mean fetch and hash the current terms
// document, schema failures mean correct the members. Field lists computed from
// a revision the caller has not read yet describe requirements that may already
// have changed, so they would send it to fix the wrong thing.
func TestExchangeRegister_TermsAnswerBeforeTheSchema(t *testing.T) {
	h := newGateHarness(t)
	a := h.newAgent(t, "termsfirst.example")

	_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, nonConformingRegistration()), staleTermsDigest(),
	)))
	if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
		t.Fatalf("code = %v, want FailedPrecondition (err=%v)", got, err)
	}
	failure := registrationFailure(t, err)
	want := rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE
	if got := failure.GetReason(); got != want {
		t.Errorf("reason = %v, want %v — INVALID_REGISTRATION_DATA here would mean the "+
			"schema gate answered a caller that cannot yet have read the current terms",
			got, want)
	}
	if n := len(failure.GetFieldErrors()); n != 0 {
		t.Errorf("%d field error(s) on a stale-digest refusal, want 0 — the proto allows "+
			"them only with INVALID_REGISTRATION_DATA, and these would describe a revision "+
			"the caller has not read", n)
	}
	assertNoRegistrationSideEffects(t, h, a)
}

// TestExchangeRegister_MalformedTermsDigestIsRefusedAtIngest pins what a caller
// gets for a digest that is not a digest at all.
//
// RegisterRequest.terms_digest carries a protovalidate pattern, and the
// bidirectional validation interceptor enforces it before the handler runs. So a
// malformed value never reaches the terms gate, and the caller is told the field
// is malformed — correct the syntax — rather than that its terms are stale —
// re-read the terms document. Those are two different remedies and nothing else
// in this package observes the difference.
//
// The harness publishes both gates on purpose. If the interceptor stopped
// refusing, the value would reach acceptedTermsDigest and come back as
// FailedPrecondition with TERMS_DIGEST_STALE, so this assertion changes. On a
// harness publishing no digest the submitted value is ignored altogether and the
// same loss would leave no trace here.
func TestExchangeRegister_MalformedTermsDigestIsRefusedAtIngest(t *testing.T) {
	for _, tc := range testutil.MalformedTermsDigests {
		// The shared table is a MANIFEST-configuration table, and one of its
		// entries pairs a well-formed digest with a missing terms URI. That is a
		// configuration fault, not a malformed field, and sending it here would
		// register successfully. Only the entries whose digest is itself
		// malformed belong on this RPC.
		if tc.Digest == testutil.TermsDigest {
			continue
		}
		t.Run(tc.Name, func(t *testing.T) {
			h := newGateHarness(t)
			a := h.newAgent(t, "malformeddigest.example")

			_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
				testutil.RegistrationStruct(t, conformingRegistration()), tc.Digest,
			)))
			if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
			}
			assertNoRegistrationFailureAttached(t, err)
			assertNoRegistrationSideEffects(t, h, a)
		})
	}
}

// assertNoRegistrationFailureAttached checks that no attached ErrorDetail names
// a registration failure.
//
// It ranges over testutil.ErrorDetails rather than calling
// testutil.SingleErrorDetail, because carrying NO RAMP ErrorDetail is a pass
// here. The interceptor refuses before the Exchange builds an envelope, so the
// rejection carries protovalidate's own violation detail and may carry no
// rampv1.ErrorDetail at all — SingleErrorDetail fails the test in exactly that
// case, which is the outcome this helper exists to accept.
func assertNoRegistrationFailureAttached(t *testing.T, err error) {
	t.Helper()
	for _, detail := range testutil.ErrorDetails(t, err) {
		if failure := detail.GetRegistrationFailure(); failure != nil {
			t.Errorf("a malformed terms_digest carries registration_failure %v — it is "+
				"refused as a malformed field before the gate runs, and the caller's "+
				"remedy is to correct the syntax, not to re-read the terms", failure)
		}
	}
}
