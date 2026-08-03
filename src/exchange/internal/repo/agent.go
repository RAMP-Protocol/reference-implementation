package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// Agent is the domain view of an agents row.
type Agent struct {
	ID            string
	PublicKey     []byte
	DiscoveryURL  string
	RequesterType string
	// BillingRef is the Exchange-generated billing account id; empty means
	// "not registered for paid content yet" (ADR-021 D3). Written once via
	// SetBillingRef; Upsert never touches it, so key rotation re-upserts
	// leave it intact.
	BillingRef string
}

// AgentRepo is the narrow agent contract.
//
// Every method's agent id is reduced through agentid.FromDirectory before it
// reaches SQL — see agentKey. The agents table is keyed on an agent's CANONICAL
// directory host, and that invariant used to hold only because each of six call
// sites across three layers remembered to normalize first. It held by audit
// rather than by construction, so the seventh caller to write
// s.agents.ByID(ctx, someDirectory) would silently create the duplicate row the
// whole derivation exists to prevent. Enforcing it here makes the column's owner
// responsible for its own column, which is the one place a caller cannot forget.
//
// Callers that already normalize are unaffected: agentid.FromDirectory is
// idempotent, so the second pass is a documented no-op rather than a second
// derivation that has to agree with the first.
type AgentRepo interface {
	ByID(ctx context.Context, agentID string) (Agent, error)
	Upsert(ctx context.Context, a Agent) (Agent, error)
	SetBillingRef(ctx context.Context, agentID, billingRef string) (Agent, error)
}

// ErrAgentNotFound is returned when an agent lookup has no match.
var ErrAgentNotFound = errors.New("repo: agent not found")

// ErrAgentIDNotAHost is returned when a value handed to this repo as an agent id
// does not name a host. Such a value can never key a row — the column holds
// canonical directory hosts — so it is refused rather than passed to SQL, where
// it would either miss silently on a read or create an unreachable row on a
// write.
//
// It is an alias of agentid.ErrNotAHost, not a second sentinel: one condition,
// one thing to match on. A caller may use either name; errors.Is answers the same.
var ErrAgentIDNotAHost = agentid.ErrNotAHost

// NewAgentRepo composes an AgentRepo over a sqlc.Querier.
func NewAgentRepo(q sqlc.Querier) AgentRepo { return &agentRepo{q: q} }

type agentRepo struct{ q sqlc.Querier }

// agentKey reduces a caller-supplied agent id to the string the column is keyed
// on. It is the single gate every method below passes through, so the invariant
// is a property of the repository rather than of the callers.
func agentKey(agentID string) (string, error) {
	// No re-wrap: FromDirectory already reports agentid.ErrNotAHost, which is what
	// ErrAgentIDNotAHost names. Wrapping it again only lengthened the chain.
	return agentid.FromDirectory(agentID)
}

func (r *agentRepo) ByID(ctx context.Context, agentID string) (Agent, error) {
	key, err := agentKey(agentID)
	if err != nil {
		return Agent{}, err
	}
	row, err := r.q.GetAgent(ctx, key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Agent{}, ErrAgentNotFound
		}
		return Agent{}, fmt.Errorf("get agent: %w", err)
	}
	return agentFromRow(row), nil
}

func (r *agentRepo) Upsert(ctx context.Context, a Agent) (Agent, error) {
	key, err := agentKey(a.ID)
	if err != nil {
		return Agent{}, err
	}
	row, err := r.q.UpsertAgent(ctx, sqlc.UpsertAgentParams{
		AgentID:       key,
		PublicKey:     a.PublicKey,
		DiscoveryUrl:  pgText(a.DiscoveryURL),
		RequesterType: sqlc.RampRequesterType(a.RequesterType),
	})
	if err != nil {
		return Agent{}, fmt.Errorf("upsert agent: %w", err)
	}
	return agentFromRow(row), nil
}

// SetBillingRef stores the billing account id for an agent, first write wins.
// The UPDATE's billing_ref IS NULL guard makes a repeat call a no-op; on zero
// rows the row is re-read and the stored ref wins (ADR-021 D4), or
// ErrAgentNotFound surfaces if the agent does not exist at all.
func (r *agentRepo) SetBillingRef(ctx context.Context, agentID, billingRef string) (Agent, error) {
	key, err := agentKey(agentID)
	if err != nil {
		return Agent{}, err
	}
	row, err := r.q.SetAgentBillingRef(ctx, sqlc.SetAgentBillingRefParams{
		AgentID:    key,
		BillingRef: pgText(billingRef),
	})
	if err == nil {
		return agentFromRow(row), nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, fmt.Errorf("set agent billing ref: %w", err)
	}
	return r.ByID(ctx, key)
}

func agentFromRow(row sqlc.RampAgent) Agent {
	return Agent{
		ID:            row.AgentID,
		PublicKey:     row.PublicKey,
		DiscoveryURL:  textOrEmpty(row.DiscoveryUrl),
		RequesterType: string(row.RequesterType),
		BillingRef:    textOrEmpty(row.BillingRef),
	}
}
