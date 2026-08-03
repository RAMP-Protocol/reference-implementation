package repo

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauth"
)

// PgxOAuthRepo backs oauth.Store over the sqlc Querier.
type PgxOAuthRepo struct {
	q *sqlc.Queries
}

// NewOAuthRepo constructs an OAuth authorization-server repo over the given pool.
func NewOAuthRepo(pool *pgxpool.Pool) *PgxOAuthRepo {
	return &PgxOAuthRepo{q: sqlc.New(pool)}
}

// RegisterClient persists a dynamically-registered client. RedirectURIs is
// normalized to a non-nil slice so a nil input maps to an empty SQL array, not NULL.
func (r *PgxOAuthRepo) RegisterClient(ctx context.Context, c oauth.Client) (oauth.Client, error) {
	redirects := c.RedirectURIs
	if redirects == nil {
		redirects = []string{}
	}
	row, err := r.q.RegisterOAuthClient(ctx, sqlc.RegisterOAuthClientParams{
		ClientID:     c.ID,
		RedirectUris: redirects,
		ClientName:   c.Name,
	})
	if err != nil {
		return oauth.Client{}, mapWriteErr(err, oauth.ErrUnavailable, fmt.Sprintf("register client %q", c.ID))
	}
	return toClient(row), nil
}

// ClientByID resolves a registered client, translating pgx.ErrNoRows to
// oauth.ErrClientNotFound.
func (r *PgxOAuthRepo) ClientByID(ctx context.Context, clientID string) (oauth.Client, error) {
	row, err := r.q.GetOAuthClient(ctx, clientID)
	if err != nil {
		return oauth.Client{}, mapReadErr(err, oauth.ErrClientNotFound, oauth.ErrUnavailable,
			fmt.Sprintf("get client %q", clientID))
	}
	return toClient(row), nil
}

// IssueCode stores a one-time authorization code under codeHash.
func (r *PgxOAuthRepo) IssueCode(ctx context.Context, codeHash string, c oauth.Code) error {
	_, err := r.q.IssueAuthzCode(ctx, sqlc.IssueAuthzCodeParams{
		CodeHash:      codeHash,
		ClientID:      c.ClientID,
		RedirectUri:   c.RedirectURI,
		PkceChallenge: c.PKCEChallenge,
		Subject:       c.Subject,
		ExpiresAt:     pgtype.Timestamptz{Time: c.ExpiresAt, Valid: true},
	})
	if err != nil {
		return mapWriteErr(err, oauth.ErrUnavailable, "issue authz code")
	}
	return nil
}

// GetCode reads a code's bound fields without consuming it, translating
// pgx.ErrNoRows (an unknown code) to oauth.ErrCodeNotFound. A consumed code is
// still returned; the caller detects reuse when the subsequent ConsumeCode finds
// nothing left to burn.
func (r *PgxOAuthRepo) GetCode(ctx context.Context, codeHash string) (oauth.Code, error) {
	row, err := r.q.GetAuthzCode(ctx, codeHash)
	if err != nil {
		return oauth.Code{}, mapReadErr(err, oauth.ErrCodeNotFound, oauth.ErrUnavailable, "get authz code")
	}
	return toCode(row), nil
}

// ConsumeCode atomically redeems the code, translating "no unconsumed row" (a
// second redemption or an unknown code) to oauth.ErrCodeNotFound.
func (r *PgxOAuthRepo) ConsumeCode(ctx context.Context, codeHash string) (oauth.Code, error) {
	row, err := r.q.ConsumeAuthzCode(ctx, codeHash)
	if err != nil {
		return oauth.Code{}, mapReadErr(err, oauth.ErrCodeNotFound, oauth.ErrUnavailable, "consume authz code")
	}
	return toCode(row), nil
}

func toClient(row sqlc.IdentityOauthClient) oauth.Client {
	return oauth.Client{
		ID:           row.ClientID,
		RedirectURIs: row.RedirectUris,
		Name:         row.ClientName,
	}
}

func toCode(row sqlc.IdentityOauthAuthzCode) oauth.Code {
	return oauth.Code{
		ClientID:      row.ClientID,
		RedirectURI:   row.RedirectUri,
		PKCEChallenge: row.PkceChallenge,
		Subject:       row.Subject,
		ExpiresAt:     row.ExpiresAt.Time,
	}
}

var _ oauth.Store = (*PgxOAuthRepo)(nil)
