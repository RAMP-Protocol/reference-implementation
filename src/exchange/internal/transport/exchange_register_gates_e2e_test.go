//go:build integration

package transport_test

import (
	"errors"
	"strings"
	"sync"
	"testing"

	connect "connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/regschema"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor"
)

// This file covers the Register gates an Exchange takes on by PUBLISHING them:
// the registration schema it serves as account_registration.data_schema, and the
// terms digest it serves as terms_digest. Publishing either is the enforcement
// switch — an Exchange that advertises a shape has committed to refusing a
// payload that does not match it.
//
// Kept separate from exchange_register_e2e_test.go (the core account flow) and
// exchange_register_size_limit_e2e_test.go (the payload bounds) so each file
// stays a single scenario.

// registrationAuditAction is the audit_log action a first registration writes.
// It names the service method, the same way every other audit action does —
// including SetDefaultAgentCredit, which has no RPC of its own.
//
// This literal is written out here ON PURPOSE rather than read from production.
// It is the filter the row count below is taken through, so pointing it at
// production's own constant would make it follow production wherever production
// goes: a changed token would still match itself, "exactly 1 row" would still
// hold, and the test would stop detecting the change. The duplication is the
// check.
const registrationAuditAction = "Register"

// conformingRegistration satisfies testutil.RegistrationSchemaJSON: both
// required members are present and billing_email carries an @.
func conformingRegistration() map[string]any {
	return map[string]any{
		"company_name":  "Stoa Press",
		"billing_email": "billing@publisher.example",
		"vat_id":        "XX123456789",
	}
}

// nonConformingRegistration breaks the shared schema in the two ways it can be
// broken: company_name is required and absent, and billing_email is present but
// fails its pattern because it has no @.
//
// vat_id is deliberately NOT used to drive a refusal. The shared schema gives it
// a bare string type with no pattern, so any string satisfies it and a test
// built on a "malformed" vat_id would pass without the gate doing anything.
func nonConformingRegistration() map[string]any {
	return map[string]any{"billing_email": "billing-at-publisher.example"}
}

// staleTermsDigest is well-formed and different from the digest the Exchange
// publishes: the shared revised-terms fixture, which hashes a different input
// from the one testutil.TermsDigest names.
//
// It must be well-formed. RegisterRequest.terms_digest carries a protovalidate
// pattern that the bidirectional validation interceptor enforces at ingest, so a
// syntactically invalid value — the kind testutil.MalformedTermsDigests holds —
// is refused before the handler runs and never reaches THIS gate. The case that
// pins what a caller gets for a malformed value is
// TestExchangeRegister_MalformedTermsDigestIsRefusedAtIngest below.
func staleTermsDigest() string {
	return testutil.RevisedTermsDigest
}

// mustSchema loads the shared registration schema the way the composition root
// does, so the gate enforces exactly the document the manifest publishes.
func mustSchema(t *testing.T) *regschema.Schema {
	t.Helper()
	s, err := regschema.Load(testutil.RegistrationSchemaJSON)
	if err != nil {
		t.Fatalf("load the shared registration schema: %v", err)
	}
	return s
}

// newHarnessPublishing is a Register harness that publishes exactly what it is
// handed: a nil schema, or an empty terms digest, is a gate this Exchange does
// not publish and therefore does not enforce. The two values are separate
// configuration, so publishing only one of them is a real deployment shape and
// the gate-matrix test needs to be able to build it.
func newHarnessPublishing(t *testing.T, schema *regschema.Schema, termsDigest string) *registerHarness {
	t.Helper()
	return newRegisterHarnessWith(t, registerHarnessOptions{
		billing:     billing.NewInMemoryAdapter(billing.InMemoryOptions{}),
		regSchema:   schema,
		termsDigest: termsDigest,
	})
}

// newGateHarness publishes both the shared schema and the shared terms digest,
// so both gates are live.
func newGateHarness(t *testing.T) *registerHarness {
	t.Helper()
	return newHarnessPublishing(t, mustSchema(t), testutil.TermsDigest)
}

// registrationAuditRows returns the registration rows written for the harness's
// tenant.
//
// Tier-2 repository read (Testing Doctrine §9): the audit log has no public read
// surface on the Exchange's Connect plane at all — the admin routes are
// deliberately absent from this harness and none of them reads the log. The
// production AuditRepo is the highest surface that reaches it.
func registrationAuditRows(t *testing.T, h *registerHarness) []repo.AuditRecord {
	t.Helper()
	all, err := repo.NewAuditRepo(h.queries).ByTenant(h.ctx, h.tenantID)
	if err != nil {
		t.Fatalf("AuditRepo.ByTenant: %v", err)
	}
	var out []repo.AuditRecord
	for _, rec := range all {
		if rec.Action == registrationAuditAction {
			out = append(out, rec)
		}
	}
	return out
}

// assertStoredTermsDigest checks the acceptance this registration recorded, read
// back through GetAccountStatus, where want == "" means no digest was recorded at
// all.
//
// The empty string is an unambiguous stand-in for absence here: production stores
// either NULL, when the Exchange publishes no digest and so nothing was
// accepted, or the published digest, which is never empty — an unset terms
// digest in the Exchange configuration is exactly what "publishes no digest"
// means. The wire keeps the two states apart, since terms_digest is optional, and
// this helper does not lose that.
//
// The read goes through the PUBLIC surface (Testing Doctrine §9 tier 1): the
// write travels Register RPC → service → repo → Postgres, and the value comes
// back out of GetAccountStatus, so the round trip is a protocol one end to end and
// never reaches past a layer. That is only possible because the protocol now
// carries GetAccountStatusResponse.terms_digest; before it did, this assertion
// had to stop at the repository.
func assertStoredTermsDigest(t *testing.T, h *registerHarness, a *registerAgent, want string) {
	t.Helper()
	resp, err := a.client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
	if err != nil {
		t.Fatalf("GetAccountStatus: %v", err)
	}
	if got := resp.Msg.GetTermsDigest(); got != want {
		t.Errorf("terms_digest = %q, want %q", got, want)
	}
}

// assertNoRegistrationSideEffects proves a refused Register wrote NOTHING. A
// test that only reads the returned error would pass just as happily against a
// gate that refused after writing half the registration, which is the failure
// worth catching: an account created for a caller that was told it has none.
//
// Five things must be absent, and each is checked through the highest surface
// that reaches it:
//
//   - the account, through GetAccountStatus — the public read surface, which
//     answers NotFound for an identity carrying no billing_ref;
//   - the billing_ref itself, through AgentRepo (tier-2, for the reason below).
//     GetAccountStatus is not a substitute: it answers NotFound in more than one
//     situation, including a non-empty billing_ref that points at no
//     system-of-record account, so a refusal that wrote the ref but not the
//     account would still satisfy the check above;
//   - the accepted terms digest, through AgentRepo. GetAccountStatus does return
//     the digest, so a SUCCESSFUL registration is checked through it, but here
//     there is no account for it to answer about: the RPC reports NotFound and
//     never reads the row. That leaves the production AgentRepo as the highest
//     surface that reaches the column on this path, which is a tier-2 assertion
//     (Testing Doctrine §9) for a reason that no public read surface can remove;
//   - the system-of-record account, under the first candidate id the
//     deterministic generator would have minted had the flow reached it;
//   - the audit row, through AuditRepo (tier-2 for the reason above).
func assertNoRegistrationSideEffects(t *testing.T, h *registerHarness, a *registerAgent) {
	t.Helper()
	_, err := a.client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest()))
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Errorf("GetAccountStatus after a refused Register = %v, want NotFound "+
			"(a refusal must leave no account) (err=%v)", got, err)
	}
	agent, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, a.id)
	if err != nil {
		t.Fatalf("AgentRepo.ByID(%q): %v", a.id, err)
	}
	if agent.BillingRef != "" {
		t.Errorf("billing_ref = %q after a refused Register, want empty", agent.BillingRef)
	}
	if agent.AcceptedTermsDigest != nil {
		t.Errorf("accepted_terms_digest = %q after a refused Register, want none",
			*agent.AcceptedTermsDigest)
	}
	if _, err := h.sorAdapter.IsActive(h.ctx, "billing-ref-1"); !errors.Is(err, sor.ErrAccountNotFound) {
		t.Errorf("the system of record holds an account for the first candidate id after a "+
			"refused Register (err=%v, want ErrAccountNotFound)", err)
	}
	if rows := registrationAuditRows(t, h); len(rows) != 0 {
		t.Errorf("%d %s audit row(s) after a refused Register, want 0",
			len(rows), registrationAuditAction)
	}
}

// assertExchangeDomain checks a fault envelope names the exchange service.
func assertExchangeDomain(t *testing.T, detail *rampv1.ErrorDetail) {
	t.Helper()
	if got := detail.GetDomain(); got != exchangeServiceDomainLiteral {
		t.Errorf("ErrorDetail.Domain = %q, want %q — every Exchange fault attributes "+
			"via Domain, and a client filters on this exact value",
			got, exchangeServiceDomainLiteral)
	}
}

// registrationFailure decodes the typed RegistrationFailure detail attached to a
// refused Register, failing the test when the error carries none.
func registrationFailure(t *testing.T, err error) *rampv1.RegistrationFailure {
	t.Helper()
	detail := testutil.SingleErrorDetail(t, err)
	assertExchangeDomain(t, detail)
	failure := detail.GetRegistrationFailure()
	if failure == nil {
		t.Fatalf("ErrorDetail carries no registration_failure reason: %v", detail)
	}
	// A typed refusal carries NO metadata. The reason oneof is the whole
	// machine-readable payload here — the per-member field_errors for a schema
	// refusal, the condition token for a stale digest — and metadata rides only
	// the reasonless generic envelope a bounds refusal takes. Nothing asserted
	// this before, so the split existed only in the constructors' comment.
	if md := detail.GetMetadata(); len(md) > 0 {
		t.Errorf("a typed registration refusal carries metadata %v, want none — metadata "+
			"rides only the reasonless generic envelope", md)
	}
	return failure
}

// TestExchangeRegister_ConformingPayloadIsAccepted is the positive leg: with
// both gates live, a payload that satisfies the published schema and names the
// published terms digest registers normally.
func TestExchangeRegister_ConformingPayloadIsAccepted(t *testing.T) {
	h := newGateHarness(t)
	a := h.newAgent(t, "conforming.example")

	resp, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, conformingRegistration()), testutil.TermsDigest,
	)))
	if err != nil {
		t.Fatalf("Register with a conforming payload: %v", err)
	}
	if got := resp.Msg.GetBillingRef(); got != "billing-ref-1" {
		t.Errorf("billing_ref = %q, want billing-ref-1 (the first candidate)", got)
	}
}

// TestExchangeRegister_NonConformingPayloadIsRefused drives a payload that
// breaks the published schema and checks the whole refusal: the transport code,
// the machine-readable reason, the per-field list naming BOTH failures, and the
// absence of every side effect.
func TestExchangeRegister_NonConformingPayloadIsRefused(t *testing.T) {
	h := newGateHarness(t)
	a := h.newAgent(t, "nonconforming.example")

	_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, nonConformingRegistration()), testutil.TermsDigest,
	)))
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("code = %v, want InvalidArgument (err=%v)", got, err)
	}
	failure := registrationFailure(t, err)
	want := rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA
	if got := failure.GetReason(); got != want {
		t.Errorf("reason = %v, want %v", got, want)
	}
	// Both failures are reported, not just the first: an agent that fixed one
	// member per round trip would need as many refusals as it has mistakes.
	paths := map[string]bool{}
	for _, fe := range failure.GetFieldErrors() {
		paths[fe.GetPath()] = true
		if fe.GetError() == "" {
			t.Errorf("field error for %q carries no text", fe.GetPath())
		}
	}
	// The root pointer is the empty string: `required` fails on the object, not
	// on the member that is missing from it.
	for _, want := range []string{"", "/billing_email"} {
		if !paths[want] {
			t.Errorf("field_errors carry no entry for path %q; got %v", want, paths)
		}
	}
	assertNoRegistrationSideEffects(t, h, a)
}

// TestExchangeRegister_TermsDigestIsEnforced drives the two refusing cases of
// the terms gate. Both must reach the SAME reason: naming a superseded revision
// and naming none have one remedy — fetch the terms this Exchange publishes,
// hash them, and register again.
//
// Neither carries field errors. The proto allows field_errors only alongside
// INVALID_REGISTRATION_DATA, so a stale-digest refusal that carried any would be
// an invalid message on the wire.
func TestExchangeRegister_TermsDigestIsEnforced(t *testing.T) {
	cases := []struct {
		name   string
		digest string
	}{
		{"a superseded revision", staleTermsDigest()},
		{"no revision at all", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newGateHarness(t)
			a := h.newAgent(t, "terms.example")

			_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
				testutil.RegistrationStruct(t, conformingRegistration()), tc.digest,
			)))
			if got := connect.CodeOf(err); got != connect.CodeFailedPrecondition {
				t.Fatalf("code = %v, want FailedPrecondition (err=%v)", got, err)
			}
			failure := registrationFailure(t, err)
			want := rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE
			if got := failure.GetReason(); got != want {
				t.Errorf("reason = %v, want %v", got, want)
			}
			if n := len(failure.GetFieldErrors()); n != 0 {
				t.Errorf("%d field error(s) on a stale-digest refusal, want 0 — the proto "+
					"allows them only with INVALID_REGISTRATION_DATA", n)
			}
			assertNoRegistrationSideEffects(t, h, a)
		})
	}
}

// TestExchangeRegister_RecordsTheAcceptedTermsDigest proves a successful
// registration keeps the acceptance. The terms are versioned, so "which revision
// did this account agree to" is a question the operator will be asked long after
// the request is gone, and nothing else in the system records the answer.
func TestExchangeRegister_RecordsTheAcceptedTermsDigest(t *testing.T) {
	h := newGateHarness(t)
	a := h.newAgent(t, "accepted.example")

	if _, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, conformingRegistration()), testutil.TermsDigest,
	))); err != nil {
		t.Fatalf("Register: %v", err)
	}

	rows := registrationAuditRows(t, h)
	if len(rows) != 1 {
		t.Fatalf("%d %s audit row(s), want exactly 1", len(rows), registrationAuditAction)
	}
	rec := rows[0]
	if !strings.Contains(string(rec.Detail), testutil.TermsDigest) {
		t.Errorf("audit detail %s does not record the accepted digest %q",
			rec.Detail, testutil.TermsDigest)
	}
	if rec.Actor == nil || *rec.Actor != a.id {
		t.Errorf("audit actor = %v, want %q — a registration is signed by the agent it "+
			"registers, so there is a real actor to record", rec.Actor, a.id)
	}
	if rec.SourceAddr == "" {
		t.Error("audit source_addr is empty; the column is NOT NULL and the peer address " +
			"is what fills it")
	}

	assertStoredTermsDigest(t, h, a, testutil.TermsDigest)
}

// TestExchangeRegister_NoSchemaPublishedPassesThrough is the pass-through case
// an Exchange publishing no schema is entitled to: the payload is not inspected
// and reaches the system of record unchanged, exactly as every deployment
// behaved before the field existed. The payload used here is the one the gate
// tests refuse, so a gate that ran anyway would show up as a refusal.
func TestExchangeRegister_NoSchemaPublishedPassesThrough(t *testing.T) {
	h := newRegisterHarness(t)
	a := h.newAgent(t, "noschema.example")

	resp, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(
		testutil.RegistrationStruct(t, nonConformingRegistration()),
	)))
	if err != nil {
		t.Fatalf("Register with no schema published: %v", err)
	}
	// Read the stored account back through the SoR port itself. OnRegister is
	// idempotent on the subdomain and returns the ORIGINALLY stored account
	// unchanged, so a repeat carrying a different candidate id and no data is a
	// read: whatever comes back was written by the registration above.
	acct, err := h.sorAdapter.OnRegister(h.ctx, sor.OnRegisterRequest{
		BillingRef: "read-back-candidate", Subdomain: a.id,
	})
	if err != nil {
		t.Fatalf("read the stored account back: %v", err)
	}
	if got := acct.BillingRef; got != resp.Msg.GetBillingRef() {
		t.Errorf("stored billing_ref = %q, want %q — the stored id wins over a later candidate",
			got, resp.Msg.GetBillingRef())
	}
	if got := acct.Extra["billing_email"]; got != "billing-at-publisher.example" {
		t.Errorf("stored billing_email = %q, want the submitted value unchanged", got)
	}
	// No digest is published either, so nothing was accepted and nothing is
	// recorded. NULL is the state that says so; an empty string would claim an
	// acceptance the Exchange cannot back with a terms document.
	assertStoredTermsDigest(t, h, a, "")
}

// TestExchangeRegister_ConcurrentFirstRegistrationsAuditOnce drives two first
// registrations for the SAME agent at once. One guarded UPDATE wins and the
// other matches zero rows; both callers get the stored account back and both
// report success, so a flow that appended an audit row on every success would
// record two registrations for one account.
//
// The overlap is FORCED, not hoped for. A sequential repeat never reaches this:
// the second call takes Register's fast path and never enters firstRegister at
// all. billingRefGen is called inside firstRegister, after the fast-path check,
// so a generator that blocks the first caller until the second one also reaches
// it puts both past the fast path by construction. Without that barrier the two
// requests can serialize and the test passes while proving nothing.
func TestExchangeRegister_ConcurrentFirstRegistrationsAuditOnce(t *testing.T) {
	const callers = 2
	var (
		mu      sync.Mutex
		arrived int
		n       int
	)
	// Released once every caller is inside firstRegister.
	barrier := make(chan struct{})
	gen := func() string {
		mu.Lock()
		arrived++
		if arrived == callers {
			close(barrier)
		}
		n++
		ref := "billing-ref-" + string(rune('0'+n))
		mu.Unlock()
		<-barrier
		return ref
	}

	h := newRegisterHarnessWith(t, registerHarnessOptions{
		billing:       billing.NewInMemoryAdapter(billing.InMemoryOptions{}),
		billingRefGen: gen,
	})
	a := h.newAgent(t, "concurrent.example")

	refs := make([]string, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(
				testutil.RegistrationStruct(t, conformingRegistration()),
			)))
			errs[i] = err
			if err == nil {
				refs[i] = resp.Msg.GetBillingRef()
			}
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("concurrent Register %d: %v", i, err)
		}
	}
	if refs[0] != refs[1] {
		t.Errorf("the two callers got different billing refs (%q and %q); the account is one "+
			"account and both must be told the stored id", refs[0], refs[1])
	}
	if rows := registrationAuditRows(t, h); len(rows) != 1 {
		t.Errorf("%d %s audit row(s) after two concurrent first registrations, want exactly 1 "+
			"— only the caller whose guarded update won actually registered anything",
			len(rows), registrationAuditAction)
	}
}

// TestExchangeRegister_RepeatUnderLiveGatesTakesTheFastPath drives a SECOND
// Register for an already-registered agent with both gates live, sending input
// that both gates would refuse: a payload the published schema does not match,
// and a digest that is not the published one.
//
// It must still succeed, because the fast path runs before the gates and a
// repeat accepts nothing a second time. That ordering is what keeps a published
// terms revision from breaking the replay RegisterRequest documents. Move either
// gate ahead of the fast-path check and every returning agent starts failing the
// moment the operator publishes a new terms revision: the agent presents the
// digest it accepted, the Exchange now publishes a different one, and a call
// that should have replayed a stored billing_ref is refused as stale.
//
// TestExchangeRegister_IdempotentRepeat covers the repeat itself, but it runs on
// a harness that publishes neither gate. Both gates are switched off for the
// whole of that test, so it cannot say anything about this ordering.
func TestExchangeRegister_RepeatUnderLiveGatesTakesTheFastPath(t *testing.T) {
	h := newGateHarness(t)
	a := h.newAgent(t, "gated-repeat.example")

	first, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, conformingRegistration()), testutil.TermsDigest,
	)))
	if err != nil {
		t.Fatalf("first Register: %v", err)
	}

	repeat, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, nonConformingRegistration()), staleTermsDigest(),
	)))
	if err != nil {
		t.Fatalf("repeat Register carrying input BOTH gates refuse: %v — the fast path runs "+
			"before the gates, so a repeat is never re-gated", err)
	}
	if got, want := repeat.Msg.GetBillingRef(), first.Msg.GetBillingRef(); got != want {
		t.Errorf("repeat billing_ref = %q, want %q (stable)", got, want)
	}
	// The repeat accepted nothing, so the recorded acceptance is still the one the
	// first call made: not the stale digest the repeat presented, and not NULL.
	assertStoredTermsDigest(t, h, a, testutil.TermsDigest)
	if rows := registrationAuditRows(t, h); len(rows) != 1 {
		t.Errorf("%d %s audit row(s) after a first registration and a repeat, want exactly 1 "+
			"— the repeat registered nothing", len(rows), registrationAuditAction)
	}
}

// TestExchangeRegister_EachGateIsPublishedIndependently configures the two gates
// one at a time. Every other Register test runs with both of them published
// (newGateHarness) or with neither (newRegisterHarness), so a schema gate
// accidentally conditioned on a terms digest also being configured — or the
// reverse — would pass the whole suite while refusing nothing in a deployment
// that publishes only one of the two.
//
// Each single-gate harness is driven twice: once with input its own gate must
// refuse, and once with input the OTHER gate would refuse if it were live. The
// second half proves the unpublished gate is really switched off rather than
// incidentally satisfied. It also drives the "not published, any presented ->
// ignore the value, record nothing" case, since a caller may present a digest to
// an Exchange that publishes none, and recording it would assert an acceptance
// that Exchange cannot back with a terms document.
func TestExchangeRegister_EachGateIsPublishedIndependently(t *testing.T) {
	cases := []struct {
		name      string
		schema    *regschema.Schema
		published string
		payload   map[string]any
		presented string
		// wantReason is the machine-readable reason the refusal carries.
		// UNSPECIFIED means the row is ACCEPTED instead: the gate that would have
		// refused this input is not published on this harness.
		wantReason rampv1.RegistrationFailureReason
		wantCode   connect.Code
		// wantRecorded is the digest an accepted registration stores, "" for none.
		// Read only on an accepted row.
		wantRecorded string
	}{
		{
			name:       "the schema gate alone refuses a payload that does not match it",
			schema:     mustSchema(t),
			payload:    nonConformingRegistration(),
			wantReason: rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_INVALID_REGISTRATION_DATA,
			wantCode:   connect.CodeInvalidArgument,
		},
		{
			name:         "the schema gate alone ignores a digest presented to an Exchange publishing none",
			schema:       mustSchema(t),
			payload:      conformingRegistration(),
			presented:    staleTermsDigest(),
			wantRecorded: "",
		},
		{
			name:       "the terms gate alone refuses a digest that is not the published one",
			published:  testutil.TermsDigest,
			payload:    conformingRegistration(),
			presented:  staleTermsDigest(),
			wantReason: rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_TERMS_DIGEST_STALE,
			wantCode:   connect.CodeFailedPrecondition,
		},
		{
			name:         "the terms gate alone does not inspect the payload",
			published:    testutil.TermsDigest,
			payload:      nonConformingRegistration(),
			presented:    testutil.TermsDigest,
			wantRecorded: testutil.TermsDigest,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newHarnessPublishing(t, tc.schema, tc.published)
			a := h.newAgent(t, "onegate.example")

			_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
				testutil.RegistrationStruct(t, tc.payload), tc.presented,
			)))
			if tc.wantReason == rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_UNSPECIFIED {
				if err != nil {
					t.Fatalf("Register: %v — the gate that would refuse this input is not "+
						"published on this Exchange, so nothing may refuse it", err)
				}
				assertStoredTermsDigest(t, h, a, tc.wantRecorded)
				return
			}
			if got := connect.CodeOf(err); got != tc.wantCode {
				t.Fatalf("code = %v, want %v (err=%v)", got, tc.wantCode, err)
			}
			if got := registrationFailure(t, err).GetReason(); got != tc.wantReason {
				t.Errorf("reason = %v, want %v", got, tc.wantReason)
			}
			assertNoRegistrationSideEffects(t, h, a)
		})
	}
}
