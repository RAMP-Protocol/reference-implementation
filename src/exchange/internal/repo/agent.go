package repo

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
)

// Agent is the domain view of an agents row.
type Agent struct {
	ID            string
	PublicKey     []byte
	ManifestURL   string
	RequesterType string
}

// AgentRepo is the narrow agent contract.
type AgentRepo interface {
	ByID(ctx context.Context, agentID string) (Agent, error)
	Upsert(ctx context.Context, a Agent) (Agent, error)
}

// ErrAgentNotFound is returned when an agent lookup has no match.
var ErrAgentNotFound = errors.New("repo: agent not found")

// NewAgentRepo composes an AgentRepo over a sqlc.Querier.
func NewAgentRepo(q sqlc.Querier) AgentRepo { return &agentRepo{q: q} }

type agentRepo struct{ q sqlc.Querier }

func (r *agentRepo) ByID(ctx context.Context, agentID string) (Agent, error) {
	row, err := r.q.GetAgent(ctx, agentID)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return Agent{}, ErrAgentNotFound
		}
		return Agent{}, fmt.Errorf("get agent: %w", err)
	}
	return Agent{
		ID:            row.AgentID,
		PublicKey:     row.PublicKey,
		ManifestURL:   textOrEmpty(row.ManifestUrl),
		RequesterType: string(row.RequesterType),
	}, nil
}

func (r *agentRepo) Upsert(ctx context.Context, a Agent) (Agent, error) {
	row, err := r.q.UpsertAgent(ctx, sqlc.UpsertAgentParams{
		AgentID:       a.ID,
		PublicKey:     a.PublicKey,
		ManifestUrl:   pgText(a.ManifestURL),
		RequesterType: sqlc.RampRequesterType(a.RequesterType),
	})
	if err != nil {
		return Agent{}, fmt.Errorf("upsert agent: %w", err)
	}
	return Agent{
		ID:            row.AgentID,
		PublicKey:     row.PublicKey,
		ManifestURL:   textOrEmpty(row.ManifestUrl),
		RequesterType: string(row.RequesterType),
	}, nil
}
