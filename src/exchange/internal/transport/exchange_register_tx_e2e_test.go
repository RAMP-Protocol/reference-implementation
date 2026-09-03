//go:build integration

package transport_test

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"

	connect "connectrpc.com/connect"
	"github.com/jackc/pgx/v5"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/billing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// This file covers the ONE transaction in the Register flow: the account link
// and its audit row commit together, or neither lands. Kept separate from
// exchange_register_e2e_test.go (the core account flow),
// exchange_register_gates_e2e_test.go (the published schema and terms digest)
// and exchange_register_size_limit_e2e_test.go (the payload bounds) so each file
// stays a single scenario.
//
// Both tests drive Register through the real Connect router and both fail the
// transaction from the runner seam, which is the only way to reach these paths:
// nothing a caller can send makes a commit fail.

// errInjectedTxFailure is the failure both runners below inject. It is written
// to look like driver output because that is what the real failures around the
// callback are: pgx.BeginFunc returns the driver's error untouched, so this
// models the shape recordRegistration has to wrap.
//
// It carries NO claim about redaction. exchange.Error.Error() renders the cause,
// and the transport copies that string into ErrorDetail.Message, so this text
// does reach the client. Whether an internal fault should expose its cause at
// all is a boundary-wide question that this branch does not settle.
var errInjectedTxFailure = errors.New(
	"ERROR: could not serialize access due to concurrent update (SQLSTATE 40001)",
)

// rollbackAfterWriteRunner runs the real transaction, lets the callback do every
// write it would normally do, and THEN fails — so pgx rolls the whole callback
// back. That models a commit that loses a serialization conflict, and it is the
// only shape that tests atomicity.
//
// The injection has to happen INSIDE the callback. db.WithTx is pgx.BeginFunc:
// it commits when the callback returns nil. A decorator that lets the real
// runner finish and then returns an error is too late — the rows are already on
// disk, and the absence assertions would fail for the wrong reason.
//
// This is deliberately NOT the shape of failTxRunner in
// billing_ordering_integration_test.go. That one short-circuits when armed and
// never delegates, so its callback never runs at all; it models a transaction
// that could not start. Only the arming is borrowed from it.
type rollbackAfterWriteRunner struct {
	inner sharedb.TxRunner
	armed atomic.Bool
}

func (r *rollbackAfterWriteRunner) WithTx(ctx context.Context, fn func(pgx.Tx) error) error {
	if !r.armed.Load() {
		return r.inner.WithTx(ctx, fn)
	}
	return r.inner.WithTx(ctx, func(tx pgx.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return errInjectedTxFailure
	})
}

func (r *rollbackAfterWriteRunner) wrap(inner sharedb.TxRunner) sharedb.TxRunner {
	r.inner = inner
	return r
}

// beginFailRunner fails BEFORE the callback runs, which is what a transaction
// that cannot start looks like: no connection to begin on. pgx.BeginFunc returns
// that error untouched, so it is the class of failure the callback's own
// wrapping cannot cover.
type beginFailRunner struct {
	inner sharedb.TxRunner
	armed atomic.Bool
}

func (r *beginFailRunner) WithTx(ctx context.Context, fn func(pgx.Tx) error) error {
	if !r.armed.Load() {
		return r.inner.WithTx(ctx, fn)
	}
	return errInjectedTxFailure
}

func (r *beginFailRunner) wrap(inner sharedb.TxRunner) sharedb.TxRunner {
	r.inner = inner
	return r
}

// TestExchangeRegister_TransactionRollsBackBothWrites proves the guarantee
// recordRegistration exists for: the billing_ref, the accepted terms digest and
// the audit row are written in one transaction, so a failure after both
// statements have run leaves NONE of them behind.
//
// What this proves and what it does NOT. The injection lands after the whole
// callback, so it proves the callback's writes roll back together. It does not
// on its own prove they share ONE transaction: split them into two sequential
// transactions and this test still passes, because the first one rolls back and
// recordRegistration returns before the second one runs, leaving all three
// assertions true. TestExchangeRegister_AuditFailureRollsBackTheAccountWrite
// below is the leg that separates those two designs.
//
// It asserts the three Postgres writes only. The system-of-record account and
// the ledger account are created BEFORE this transaction, against two other
// backends that cannot join it, so they survive the rollback by design and a
// later Register replays the remaining steps. That is why the shared
// assertNoRegistrationSideEffects helper does not apply here: it also requires
// the SoR to hold nothing, which is true of a gate refusal and false of a
// rollback.
func TestExchangeRegister_TransactionRollsBackBothWrites(t *testing.T) {
	runner := &rollbackAfterWriteRunner{}
	h := newRegisterHarnessWith(t, registerHarnessOptions{
		billing:      billing.NewInMemoryAdapter(billing.InMemoryOptions{}),
		termsDigest:  testutil.TermsDigest,
		txRunnerWrap: runner.wrap,
	})
	a := h.newAgent(t, "rollback.example")
	// The wrap decorates the pool runner when the server is built, so arming is
	// a separate step and it happens here, immediately before the call under
	// test. Nothing in between writes through the wrapped runner: newAgent
	// generates a keypair and stands up a WBA origin without issuing a request.
	// So the armed window covers exactly the Register below.
	runner.armed.Store(true)

	_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, conformingRegistration()), testutil.TermsDigest,
	)))
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Fatalf("Register with a failing transaction = %v, want Internal (err=%v)", got, err)
	}

	// Tier-2 repository reads (Testing Doctrine §9): neither the accepted digest
	// nor the audit log has a public read surface on the Exchange's Connect
	// plane, and exposing each is filed as its own task. The billing_ref does
	// have one (GetAccountStatus), asserted first.
	if _, err := a.client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest())); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("GetAccountStatus after a rolled-back Register = %v, want NotFound",
			connect.CodeOf(err))
	}
	agent, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, a.id)
	if err != nil {
		t.Fatalf("AgentRepo.ByID(%q): %v", a.id, err)
	}
	if agent.BillingRef != "" {
		t.Errorf("billing_ref = %q after a rolled-back Register, want empty", agent.BillingRef)
	}
	if agent.AcceptedTermsDigest != nil {
		t.Errorf("accepted_terms_digest = %q after a rolled-back Register, want none",
			*agent.AcceptedTermsDigest)
	}
	if rows := registrationAuditRows(t, h); len(rows) != 0 {
		t.Errorf("%d %s audit row(s) after a rolled-back Register, want 0",
			len(rows), registrationAuditAction)
	}
}

// TestExchangeRegister_TransactionFailureIsAnExchangeFault covers the failures
// the callback's own wrapping cannot reach: the ones the runner raises AROUND
// the callback. db.WithTx is pgx.BeginFunc, so it also reports a transaction
// that could not begin and a commit that could not complete, and it returns both
// exactly as the driver produced them.
//
// Returning that result bare would put an error carrying no domain kind in front
// of the transport, which the error hierarchy forbids.
//
// Two things are asserted, and only these two: the fault carries the Exchange's
// domain, and its message names the operation that failed. Remove the wrap in
// recordRegistration and the message becomes the injected text alone, so this
// goes red.
//
// The wrap does not hide the driver's sentence — it prefixes it. The cause still
// rides the message to the client, which is a property of exchange.Error.Error()
// and the shared fault envelope rather than of this call site, so no assertion
// here claims otherwise.
func TestExchangeRegister_TransactionFailureIsAnExchangeFault(t *testing.T) {
	runner := &beginFailRunner{}
	h := newRegisterHarnessWith(t, registerHarnessOptions{
		billing:      billing.NewInMemoryAdapter(billing.InMemoryOptions{}),
		txRunnerWrap: runner.wrap,
	})
	a := h.newAgent(t, "beginfail.example")
	runner.armed.Store(true)

	_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(
		testutil.RegistrationStruct(t, conformingRegistration()),
	)))
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Fatalf("Register with an unstartable transaction = %v, want Internal (err=%v)", got, err)
	}
	detail := testutil.SingleErrorDetail(t, err)
	assertExchangeDomain(t, detail)
	if !strings.Contains(detail.GetMessage(), "record registration") {
		t.Errorf("ErrorDetail.Message = %q, want it to name the operation the Exchange was "+
			"performing; a bare runner error carries no domain kind at all",
			detail.GetMessage())
	}
}

// errInjectedAuditFailure is what the audit repo below returns when armed. It is
// deliberately not driver-shaped: this failure is raised by the repository, and
// the test asserts on rows rather than on message text.
var errInjectedAuditFailure = errors.New("injected audit append failure")

// failingAuditRepo fails the audit append from INSIDE the registration
// transaction, after the guarded account UPDATE has already run on that same
// transaction. It embeds the real repo so reads (ByTenant) still work and only
// Append is replaced.
//
// This is the injection point the runner-level failure cannot reach. A runner
// that fails around the callback tells us nothing about where inside the
// callback the statements sit; a failure raised BETWEEN the two statements does.
type failingAuditRepo struct {
	repo.AuditRepo
	armed atomic.Bool
}

func (r *failingAuditRepo) Append(ctx context.Context, tx pgx.Tx, e repo.AuditEntry) error {
	if !r.armed.Load() {
		return r.AuditRepo.Append(ctx, tx, e)
	}
	return errInjectedAuditFailure
}

func (r *failingAuditRepo) wrap(inner repo.AuditRepo) repo.AuditRepo {
	r.AuditRepo = inner
	return r
}

// TestExchangeRegister_AuditFailureRollsBackTheAccountWrite is the leg that
// proves the account write and the audit row share ONE transaction, which the
// rollback test above cannot show on its own.
//
// The account UPDATE runs first and succeeds. The audit append then fails. If
// the two share a transaction, the failure takes the UPDATE down with it and the
// agent row keeps no billing_ref and no accepted digest. Move the append into a
// second, later transaction and the first one has already committed, so the
// billing_ref and the digest survive and this test goes red.
//
// The billing_ref and the digest are the load-bearing assertions. The audit row
// is absent under BOTH designs — a later append that never runs leaves no row
// either — so its absence proves nothing here and is not asserted.
func TestExchangeRegister_AuditFailureRollsBackTheAccountWrite(t *testing.T) {
	audit := &failingAuditRepo{}
	h := newRegisterHarnessWith(t, registerHarnessOptions{
		billing:     billing.NewInMemoryAdapter(billing.InMemoryOptions{}),
		termsDigest: testutil.TermsDigest,
		auditWrap:   audit.wrap,
	})
	a := h.newAgent(t, "auditfail.example")
	// The wrap decorates the audit repo when the server is built, so arming is a
	// separate step and it happens here, immediately before the call under test.
	// newAgent issues no request, so nothing has been appended through this repo
	// yet and the armed window covers exactly the Register below. The agent's
	// self-signup does run inside that call, but it writes through agentreg's
	// repo.Upsert and appends no audit row, so it is unaffected either way.
	audit.armed.Store(true)

	_, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequestWithTerms(
		testutil.RegistrationStruct(t, conformingRegistration()), testutil.TermsDigest,
	)))
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Fatalf("Register with a failing audit append = %v, want Internal (err=%v)", got, err)
	}

	// The public read surface first, then the tier-2 repository read for the
	// digest, which has no public surface of its own (Testing Doctrine §9).
	if _, err := a.client.GetAccountStatus(h.ctx, connect.NewRequest(newAccountStatusRequest())); connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("GetAccountStatus after a failed audit append = %v, want NotFound",
			connect.CodeOf(err))
	}
	agent, err := repo.NewAgentRepo(h.queries).ByID(h.ctx, a.id)
	if err != nil {
		t.Fatalf("AgentRepo.ByID(%q): %v", a.id, err)
	}
	if agent.BillingRef != "" {
		t.Errorf("billing_ref = %q after the audit append failed, want empty — the account "+
			"write committed without its audit row, so the two are not in one transaction",
			agent.BillingRef)
	}
	if agent.AcceptedTermsDigest != nil {
		t.Errorf("accepted_terms_digest = %q after the audit append failed, want none",
			*agent.AcceptedTermsDigest)
	}
}
