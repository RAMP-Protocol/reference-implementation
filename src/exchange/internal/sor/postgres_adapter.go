package sor

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor/db/sqlc"
)

// PostgresAdapter is the production Adapter backed by the SoR's own Postgres
// database. It mints no ids: the candidate billing_ref arrives in the request
// (ADR-021 D2) and the stored one wins on a subdomain conflict (ADR-021 D4).
type PostgresAdapter struct {
	runner db.TxRunner
}

// Compile-time check that PostgresAdapter satisfies the port.
var _ Adapter = (*PostgresAdapter)(nil)

// NewPostgresAdapter wires the adapter over the narrow transaction port so the
// pool stays in wiring (cmd/server), mirroring how services receive their
// db.TxRunner.
func NewPostgresAdapter(runner db.TxRunner) *PostgresAdapter {
	return &PostgresAdapter{runner: runner}
}

// OnRegister inserts the account if its subdomain is new, or returns the
// already-stored account unchanged. Insert and conflict read-back share one
// transaction, so the read-back always observes the row the conflict fired on
// — including a row committed by a concurrent duplicate register, whose
// in-flight lock the insert waits out before resolving to DO NOTHING.
func (a *PostgresAdapter) OnRegister(ctx context.Context, req OnRegisterRequest) (Account, error) {
	if err := validateOnRegister(req); err != nil {
		return Account{}, err
	}

	profile, email, extra := mapRegistration(req.RegistrationData)
	candidate := Account{
		BillingRef: req.BillingRef,
		Subdomain:  req.Subdomain,
		Active:     req.Active,
		Email:      email,
		Profile:    profile,
		Extra:      extra,
	}

	var out Account
	err := a.runner.WithTx(ctx, func(tx pgx.Tx) error {
		repo := NewAccountRepo(sqlc.New(tx))
		stored, inserted, err := repo.InsertIfAbsent(ctx, candidate)
		if err != nil {
			return err
		}
		if !inserted {
			// An account for this subdomain already exists: return it
			// unchanged — its stored billing_ref wins over the fresh
			// candidate (ADR-021 D4).
			stored, err = repo.BySubdomain(ctx, req.Subdomain)
			if err != nil {
				return err
			}
		}
		out = stored
		return nil
	})
	if err != nil {
		return Account{}, fmt.Errorf("sor register %q: %w", req.Subdomain, err)
	}
	return out, nil
}

// IsActive reads the SoR-owned active flag. An unknown billing_ref returns
// ErrAccountNotFound; a known-but-inactive account returns (false, nil).
func (a *PostgresAdapter) IsActive(ctx context.Context, billingRef string) (bool, error) {
	if err := validateBillingRef(billingRef); err != nil {
		return false, err
	}

	var active bool
	err := a.runner.WithTx(ctx, func(tx pgx.Tx) error {
		got, err := NewAccountRepo(sqlc.New(tx)).ActiveByBillingRef(ctx, billingRef)
		if err != nil {
			return err
		}
		active = got
		return nil
	})
	if err != nil {
		return false, err
	}
	return active, nil
}
