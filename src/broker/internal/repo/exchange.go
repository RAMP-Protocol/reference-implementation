// Package repo provides narrow, domain-specific interfaces over the generated
// sqlc Querier. Handlers and services depend on these interfaces, not on the
// fat Querier directly.
package repo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db/sqlc"
)

// Exchange is the domain representation of a known exchange row.
// Decouples service logic from sqlc-generated types (repository pattern).
type Exchange struct {
	ID                string
	Domain            string
	Endpoint          string
	TrustLevel        string
	Healthy           bool
	SupportedProfiles []string
	Priority          int32
}

// ExchangeRepo is the read port handlers and services depend on. The healthy
// flag and the endpoint are not writable here: from inside request handling a
// handler could mark an exchange down, or move the address the SSRF allowlist
// compares against. Those writes live on ExchangeHealthRepo.
type ExchangeRepo interface {
	ListUnblocked(ctx context.Context) ([]Exchange, error)
	GetByDomain(ctx context.Context, domain string) (Exchange, error)
	UpsertFromBootstrap(ctx context.Context, m Exchange) (Exchange, error)
}

// ExchangeHealthRepo is the health refresher's port: read every probeable row,
// write back what each probe learned. Separate from ExchangeRepo so the write
// stays off every request-path consumer's surface (Architecture Rule 3).
// *PgxExchangeRepo satisfies both.
type ExchangeHealthRepo interface {
	ListUnblocked(ctx context.Context) ([]Exchange, error)
	SetProbeResult(ctx context.Context, exchangeID, endpoint string, healthy bool) error
}

// The trust levels an operator may give an exchange, spelled as the
// broker.trust_level enum spells them. Declared here rather than taken from the
// generated sqlc enum so services stay off the generated package; a guard test
// pins that the two agree.
const (
	TrustLevelDiscovered = "DISCOVERED"
	TrustLevelVerified   = "VERIFIED"
	TrustLevelPreferred  = "PREFERRED"
	TrustLevelBlocked    = "BLOCKED"
)

// Admission is whether the broker may route to one registry row, and it is the
// SINGLE derivation of that rule — the relay's SSRF admission, the resolve
// router's guard and the routing-skip reason all read it here. Three values
// because the callers owe three answers, split by whether the state clears on
// its own.
//
// AdmissionLive is deliberately not the zero value: a row nobody filled in must
// not read as routable.
type Admission int

const (
	// AdmissionBlocked means the operator withdrew trust. Settled, so a refusal
	// owes a final answer.
	AdmissionBlocked Admission = iota
	// AdmissionDown means trusted, but the last health probe failed. Clears
	// within a refresher interval, so a refusal owes a retryable answer.
	AdmissionDown
	// AdmissionLive means registered, trusted, and answering health probes.
	AdmissionLive
)

// Admission classifies this row. Trust is read first: an exchange can be
// BLOCKED and healthy at once, and the operator's decision outranks the probe.
func (e Exchange) Admission() Admission {
	switch {
	case e.TrustLevel == TrustLevelBlocked:
		return AdmissionBlocked
	case !e.Healthy:
		return AdmissionDown
	default:
		return AdmissionLive
	}
}

// ErrNotFound is returned when a row is not present.
var ErrNotFound = errors.New("repo: not found")

// PgxExchangeRepo wraps sqlc.Querier + pool for transactional ops.
type PgxExchangeRepo struct {
	q    *sqlc.Queries
	pool *pgxpool.Pool
}

// NewExchangeRepo constructs an ExchangeRepo backed by the given pool.
func NewExchangeRepo(pool *pgxpool.Pool) *PgxExchangeRepo {
	return &PgxExchangeRepo{q: sqlc.New(pool), pool: pool}
}

// ListUnblocked returns every non-BLOCKED exchange by priority, INCLUDING the
// ones marked unhealthy. It is the registry's only list read and deliberately
// does not pre-filter on health, because a filtered list cannot tell a caller
// that a row exists but is down.
//
// The refresher must see down rows or the flag becomes a one-way ratchet. The
// relay allowlist must see them to refuse a down exchange retryably instead of
// claiming it was never registered. Discovery reads one row through GetByDomain
// and applies Admission itself.
func (r *PgxExchangeRepo) ListUnblocked(ctx context.Context) ([]Exchange, error) {
	rows, err := r.q.ListUnblockedExchanges(ctx)
	if err != nil {
		return nil, fmt.Errorf("list unblocked exchanges: %w", err)
	}
	return rowsToExchanges(rows)
}

// GetByDomain looks up an exchange by its canonical domain.
func (r *PgxExchangeRepo) GetByDomain(ctx context.Context, domain string) (Exchange, error) {
	const q = `
SELECT exchange_id, domain, endpoint, trust_level, healthy,
       supported_profiles, priority
  FROM broker.exchanges
 WHERE domain = $1
 LIMIT 1
`
	row := r.pool.QueryRow(ctx, q, domain)
	var (
		id       string
		dom      string
		endpoint string
		trust    sqlc.BrokerTrustLevel
		healthy  bool
		profiles []byte
		priority int32
	)
	if err := row.Scan(&id, &dom, &endpoint, &trust, &healthy, &profiles, &priority); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Exchange{}, ErrNotFound
		}
		return Exchange{}, fmt.Errorf("get exchange by domain: %w", err)
	}
	supported, err := decodeProfiles(profiles)
	if err != nil {
		return Exchange{}, err
	}
	return Exchange{
		ID:                id,
		Domain:            dom,
		Endpoint:          endpoint,
		TrustLevel:        string(trust),
		Healthy:           healthy,
		SupportedProfiles: supported,
		Priority:          priority,
	}, nil
}

// CanonicalEndpoint is the single stored spelling of an endpoint: trailing "/"
// trimmed. Every write to the endpoint column goes through it, as does any
// caller comparing a freshly resolved address against the stored one.
//
// Without it a trailing-slash endpoint passes the relay's SSRF allowlist but
// the reconstructed double-slash @target-uri fails sig1 verification, breaking
// such Exchanges over the relay.
func CanonicalEndpoint(endpoint string) string {
	return strings.TrimRight(endpoint, "/")
}

// UpsertFromBootstrap reconciles a bootstrap entry into the exchanges table.
// The endpoint is canonicalized on store.
func (r *PgxExchangeRepo) UpsertFromBootstrap(ctx context.Context, m Exchange) (Exchange, error) {
	profiles, err := json.Marshal(m.SupportedProfiles)
	if err != nil {
		return Exchange{}, fmt.Errorf("marshal supported_profiles: %w", err)
	}
	row, err := r.q.UpsertExchange(ctx, sqlc.UpsertExchangeParams{
		ExchangeID:        m.ID,
		Domain:            m.Domain,
		Endpoint:          CanonicalEndpoint(m.Endpoint),
		TrustLevel:        sqlc.BrokerTrustLevel(m.TrustLevel),
		SupportedProfiles: profiles,
		Priority:          m.Priority,
	})
	if err != nil {
		return Exchange{}, fmt.Errorf("upsert exchange: %w", err)
	}
	return rowToExchange(row)
}

// SetProbeResult records what one probe pass learned: the address the
// exchange's own well-known advertises, and whether it answered /healthz.
//
// The endpoint is written too, because the well-known is the authority on where
// an exchange is and the column is a cache of it. Discovery already dials the
// resolved address and the probe measures it; leaving the column alone would
// keep a third opinion in the registry, and the relay's SSRF allowlist compares
// against exactly that column. Bootstrap seeds the row, the probe loop keeps it
// true — a restart replays the bootstrap value and the next pass corrects it.
func (r *PgxExchangeRepo) SetProbeResult(
	ctx context.Context, exchangeID, endpoint string, healthy bool,
) error {
	const q = `
UPDATE broker.exchanges
   SET healthy = $3,
       endpoint = $2,
       last_health_check = NOW(),
       updated_at = NOW()
 WHERE exchange_id = $1
`
	_, err := r.pool.Exec(ctx, q, exchangeID, CanonicalEndpoint(endpoint), healthy)
	if err != nil {
		return fmt.Errorf("set probe result: %w", err)
	}
	return nil
}

// rowsToExchanges converts a queried row set to the domain type.
func rowsToExchanges(rows []sqlc.BrokerExchange) ([]Exchange, error) {
	out := make([]Exchange, 0, len(rows))
	for i := range rows {
		m, err := rowToExchange(rows[i])
		if err != nil {
			return nil, err
		}
		out = append(out, m)
	}
	return out, nil
}

func rowToExchange(r sqlc.BrokerExchange) (Exchange, error) {
	supported, err := decodeProfiles(r.SupportedProfiles)
	if err != nil {
		return Exchange{}, err
	}
	return Exchange{
		ID:                r.ExchangeID,
		Domain:            r.Domain,
		Endpoint:          r.Endpoint,
		TrustLevel:        string(r.TrustLevel),
		Healthy:           r.Healthy,
		SupportedProfiles: supported,
		Priority:          r.Priority,
	}, nil
}

func decodeProfiles(raw []byte) ([]string, error) {
	if len(raw) == 0 {
		return nil, nil
	}
	var out []string
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, fmt.Errorf("decode supported_profiles: %w", err)
	}
	return out, nil
}

// Silence pgtype unused-import lint in stricter builds; retained for possible
// future fields (timestamps).
var _ pgtype.Text
