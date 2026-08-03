package sor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/sor/db/sqlc"
)

// AccountRepo is the narrow persistence contract the Postgres adapter drives.
// It owns the row↔domain mapping (including the extra JSONB round-trip) so the
// adapter above it speaks only in domain Accounts.
type AccountRepo interface {
	// InsertIfAbsent persists acct unless an account for its subdomain already
	// exists. inserted reports which happened: (acct, true, nil) on a fresh
	// insert; (zero, false, nil) when the subdomain already has an account —
	// the "already exists" outcome is a SUCCESS signal, never an error, and
	// the existing row is deliberately untouched (ADR-021 D4).
	InsertIfAbsent(ctx context.Context, acct Account) (stored Account, inserted bool, err error)
	// BySubdomain returns the account for a subdomain, or ErrAccountNotFound.
	BySubdomain(ctx context.Context, subdomain string) (Account, error)
	// ActiveByBillingRef returns the SoR-owned active flag for an account, or
	// ErrAccountNotFound when no account has that billing_ref.
	ActiveByBillingRef(ctx context.Context, billingRef string) (bool, error)
}

// NewAccountRepo composes an AccountRepo over a generated sqlc.Querier.
func NewAccountRepo(q sqlc.Querier) AccountRepo { return &accountRepo{q: q} }

type accountRepo struct{ q sqlc.Querier }

func (r *accountRepo) InsertIfAbsent(ctx context.Context, acct Account) (Account, bool, error) {
	extra, err := marshalExtra(acct.Extra)
	if err != nil {
		return Account{}, false, err
	}
	row, err := r.q.InsertAgentAccountIfAbsent(ctx, sqlc.InsertAgentAccountIfAbsentParams{
		BillingRef:              acct.BillingRef,
		Subdomain:               acct.Subdomain,
		Email:                   nullableText(acct.Email),
		Active:                  acct.Active,
		LegalEntity:             nullableText(acct.Profile.LegalEntity),
		JurisdictionCountry:     nullableText(acct.Profile.JurisdictionCountry),
		JurisdictionSubdivision: nullableText(acct.Profile.JurisdictionSubdivision),
		AddressLine1:            nullableText(acct.Profile.AddressLine1),
		AddressLine2:            nullableText(acct.Profile.AddressLine2),
		AddressCity:             nullableText(acct.Profile.AddressCity),
		AddressRegion:           nullableText(acct.Profile.AddressRegion),
		AddressPostalCode:       nullableText(acct.Profile.AddressPostalCode),
		AddressCountry:          nullableText(acct.Profile.AddressCountry),
		Extra:                   extra,
	})
	if err != nil {
		// ON CONFLICT (subdomain) DO NOTHING returns zero rows when the
		// account already exists, so the :one query surfaces pgx.ErrNoRows on
		// the idempotent-repeat path. That is the success signal "already
		// exists", not an error.
		if errors.Is(err, pgx.ErrNoRows) {
			return Account{}, false, nil
		}
		return Account{}, false, fmt.Errorf("insert agent account: %w", err)
	}
	stored, err := accountFromRow(row)
	if err != nil {
		return Account{}, false, err
	}
	return stored, true, nil
}

func (r *accountRepo) BySubdomain(ctx context.Context, subdomain string) (Account, error) {
	row, err := r.q.GetAgentAccountBySubdomain(ctx, subdomain)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Account{}, ErrAccountNotFound
		}
		return Account{}, fmt.Errorf("get agent account by subdomain: %w", err)
	}
	return accountFromRow(row)
}

func (r *accountRepo) ActiveByBillingRef(ctx context.Context, billingRef string) (bool, error) {
	active, err := r.q.GetAgentAccountActive(ctx, billingRef)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return false, ErrAccountNotFound
		}
		return false, fmt.Errorf("get agent account active: %w", err)
	}
	return active, nil
}

func accountFromRow(row sqlc.SorAgentAccount) (Account, error) {
	extra, err := unmarshalExtra(row.Extra)
	if err != nil {
		return Account{}, err
	}
	return Account{
		BillingRef: row.BillingRef,
		Subdomain:  row.Subdomain,
		Active:     row.Active,
		Email:      textOrZero(row.Email),
		Profile: LicensingProfile{
			LegalEntity:             textOrZero(row.LegalEntity),
			JurisdictionCountry:     textOrZero(row.JurisdictionCountry),
			JurisdictionSubdivision: textOrZero(row.JurisdictionSubdivision),
			AddressLine1:            textOrZero(row.AddressLine1),
			AddressLine2:            textOrZero(row.AddressLine2),
			AddressCity:             textOrZero(row.AddressCity),
			AddressRegion:           textOrZero(row.AddressRegion),
			AddressPostalCode:       textOrZero(row.AddressPostalCode),
			AddressCountry:          textOrZero(row.AddressCountry),
		},
		Extra: extra,
	}, nil
}

// marshalExtra encodes the unmapped registration keys as the JSONB payload.
// An empty (or nil) map becomes the canonical '{}' the column defaults to.
func marshalExtra(extra map[string]string) ([]byte, error) {
	if len(extra) == 0 {
		return []byte("{}"), nil
	}
	b, err := json.Marshal(extra)
	if err != nil {
		return nil, fmt.Errorf("marshal extra: %w", err)
	}
	return b, nil
}

// unmarshalExtra decodes the JSONB payload back to a non-nil map, mirroring
// mapRegistration's always-non-nil contract.
func unmarshalExtra(raw []byte) (map[string]string, error) {
	extra := map[string]string{}
	if len(raw) == 0 {
		return extra, nil
	}
	if err := json.Unmarshal(raw, &extra); err != nil {
		return nil, fmt.Errorf("unmarshal extra: %w", err)
	}
	return extra, nil
}

// nullableText maps the domain's ""-means-absent convention to a SQL NULL, so
// an unset licensing field stays a useful "registration incomplete" signal for
// the operator instead of an empty string.
func nullableText(s string) pgtype.Text {
	if s == "" {
		return pgtype.Text{}
	}
	return pgtype.Text{String: s, Valid: true}
}

func textOrZero(t pgtype.Text) string {
	if !t.Valid {
		return ""
	}
	return t.String
}
