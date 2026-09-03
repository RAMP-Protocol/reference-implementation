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
	// AcceptedTermsDigest is the digest of the licensing terms this account
	// accepted at registration. It is a POINTER, not a string, because the column
	// has three states and collapsing two of them would lose the distinction the
	// column exists for: nil means the Exchange published no digest when this
	// account registered, a non-nil value is the digest that was accepted, and a
	// row with no billing_ref was never registered at all. Written once by
	// SetBillingRef, in the same guarded UPDATE as BillingRef.
	AcceptedTermsDigest *string
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
	SetBillingRef(
		ctx context.Context, tx pgx.Tx, agentID, billingRef string, digest *string,
	) (Agent, bool, error)
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

// SetBillingRef stores the billing account id and the accepted terms digest for
// an agent, first write wins. The UPDATE's billing_ref IS NULL guard makes a
// repeat call a no-op; on zero rows the row is re-read and the stored ref wins
// (ADR-021 D4), or ErrAgentNotFound surfaces if the agent does not exist at all.
//
// The SECOND return says whether this call's UPDATE actually won. A caller that
// only reads the returned Agent cannot tell the winner from the loser — both get
// the stored account back — and a caller that writes an audit row on every
// success would then record two registrations for one account. Two concurrent
// first registrations for the same agent reach exactly that: both pass Register's
// fast-path check, both call this, one UPDATE matches and the other returns zero
// rows.
//
// It takes the transaction rather than running on the pool because its caller
// writes an audit row in the same commit, and a pool-bound UPDATE would commit on
// its own while only the audit insert could roll back. BOTH statements bind the
// same tx-scoped querier for the same reason plus one more: a pool-bound re-read
// inside a transaction takes a second connection, which can block until the pool
// frees one — a deadlock when the transaction holds the last one — and reads
// outside the transaction's own snapshot.
func (r *agentRepo) SetBillingRef(
	ctx context.Context, tx pgx.Tx, agentID, billingRef string, digest *string,
) (Agent, bool, error) {
	key, err := agentKey(agentID)
	if err != nil {
		return Agent{}, false, err
	}
	q := sqlc.New(tx)
	row, err := q.SetAgentBillingRef(ctx, sqlc.SetAgentBillingRefParams{
		AgentID:             key,
		BillingRef:          pgText(billingRef),
		AcceptedTermsDigest: pgTextPtr(digest),
	})
	if err == nil {
		return agentFromRow(row), true, nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return Agent{}, false, fmt.Errorf("set agent billing ref: %w", err)
	}
	row, err = q.GetAgent(ctx, key)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Agent{}, false, ErrAgentNotFound
		}
		return Agent{}, false, fmt.Errorf("get agent: %w", err)
	}
	return agentFromRow(row), false, nil
}

func agentFromRow(row sqlc.RampAgent) Agent {
	return Agent{
		ID:                  row.AgentID,
		PublicKey:           row.PublicKey,
		DiscoveryURL:        textOrEmpty(row.DiscoveryUrl),
		RequesterType:       string(row.RequesterType),
		BillingRef:          textOrEmpty(row.BillingRef),
		AcceptedTermsDigest: textFromPG(row.AcceptedTermsDigest),
	}
}
