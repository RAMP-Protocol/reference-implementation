package sor

import (
	"context"
	"sync"
)

// InMemoryAdapter is a thread-safe, map-backed reference implementation of
// Adapter, suitable for scrappy-demo and for driving the conformance suite.
// It mints no ids: OnRegister persists the candidate billing_ref the Exchange
// passes in.
//
// Accounts are keyed by subdomain (the identity / idempotency anchor); byRef
// indexes billing_ref → subdomain so IsActive can resolve an account from its
// id without scanning.
type InMemoryAdapter struct {
	mu       sync.Mutex
	accounts map[string]Account // subdomain → account
	byRef    map[string]string  // billing_ref → subdomain
}

// NewInMemoryAdapter returns an empty in-memory SoR.
func NewInMemoryAdapter() *InMemoryAdapter {
	return &InMemoryAdapter{
		accounts: map[string]Account{},
		byRef:    map[string]string{},
	}
}

// OnRegister persists a new account for a previously-unseen subdomain and
// returns it carrying the passed-in candidate billing_ref. If an account for
// the subdomain already exists, the stored account is returned unchanged and
// the request has no effect — the stored billing_ref wins even when the repeat
// passes a different candidate (ADR-021 D4).
func (a *InMemoryAdapter) OnRegister(_ context.Context, req OnRegisterRequest) (Account, error) {
	if err := validateOnRegister(req); err != nil {
		return Account{}, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if existing, ok := a.accounts[req.Subdomain]; ok {
		return cloneAccount(existing), nil
	}

	profile, email, extra := mapRegistration(req.RegistrationData)
	acct := Account{
		BillingRef: req.BillingRef,
		Subdomain:  req.Subdomain,
		Active:     req.Active,
		Email:      email,
		Profile:    profile,
		Extra:      extra,
	}
	a.accounts[req.Subdomain] = acct
	a.byRef[req.BillingRef] = req.Subdomain
	return cloneAccount(acct), nil
}

// IsActive returns the stored active flag for an account identified by its
// billing_ref. An unknown billing_ref returns ErrAccountNotFound; a
// known-but-inactive account returns (false, nil).
func (a *InMemoryAdapter) IsActive(_ context.Context, billingRef string) (bool, error) {
	if err := validateBillingRef(billingRef); err != nil {
		return false, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	subdomain, ok := a.byRef[billingRef]
	if !ok {
		return false, ErrAccountNotFound
	}
	return a.accounts[subdomain].Active, nil
}

// SetActive flips the stored active flag for the account with this billing_ref,
// returning ErrAccountNotFound for an unknown ref. It is deliberately NOT on the
// Adapter port: the SoR owns the flag and the operator changes it inside the SoR,
// out of band — never through the Exchange. This method is that out-of-band
// switch for the in-memory backend; harnesses and tests use it to model the
// operator's action. (The Postgres backend's equivalent is a direct row update
// in the SoR's own database.)
func (a *InMemoryAdapter) SetActive(billingRef string, active bool) error {
	if err := validateBillingRef(billingRef); err != nil {
		return err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	subdomain, ok := a.byRef[billingRef]
	if !ok {
		return ErrAccountNotFound
	}
	acct := a.accounts[subdomain]
	acct.Active = active
	a.accounts[subdomain] = acct
	return nil
}

// cloneAccount deep-copies the Extra map so a caller mutating the returned
// account cannot reach back into stored state.
func cloneAccount(a Account) Account {
	out := a
	if a.Extra != nil {
		extra := make(map[string]string, len(a.Extra))
		for k, v := range a.Extra {
			extra[k] = v
		}
		out.Extra = extra
	}
	return out
}
