package lifecycle

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"slices"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
)

// ErrUnknownThumbprint is returned when the named thumbprint is neither a key the
// agent currently holds nor one already on its revocation list — an operator naming a
// key that was never this agent's, not a key to kill. (An already-revoked key counts
// as known, so re-running an interrupted revocation stays idempotent rather than
// tripping this.)
var ErrUnknownThumbprint = errors.New("lifecycle: thumbprint is not a key of this subdomain")

// KeyCustody is the slice of the KeyStore the revoker needs: enumerate an agent's
// keys (to confirm a thumbprint is really theirs) and erase one. *keystore.VaultStore
// satisfies it.
type KeyCustody interface {
	List(ctx context.Context, subdomain string) ([]keystore.Key, error)
	Destroy(ctx context.Context, ref keystore.Ref) error
}

// RevocationWriter is the persistence the revoker drives: record a thumbprint as
// revoked (advancing the monotonic as_of) and read the current set (for the
// belongs-to-agent check that keeps a re-run idempotent). *repo.PgxRevocationRepo
// satisfies it.
type RevocationWriter interface {
	Revoke(ctx context.Context, subdomain, thumbprint string, nowEpoch int64) (int64, error)
	BySubdomain(ctx context.Context, subdomain string) (asOf int64, revoked []string, err error)
}

// Revoker is the operator's emergency lever: it kills one of an agent's keys.
type Revoker struct {
	keys        KeyCustody
	revocations RevocationWriter
	invalidator Invalidator
	clock       clock.Clock
	logger      *slog.Logger
}

// NewRevoker wires a Revoker. A nil logger falls back to slog.Default so a caller
// that has not built one still gets the audit line every revocation emits.
func NewRevoker(
	keys KeyCustody, revocations RevocationWriter, invalidator Invalidator,
	clk clock.Clock, logger *slog.Logger,
) *Revoker {
	if logger == nil {
		logger = slog.Default()
	}
	return &Revoker{
		keys:        keys,
		revocations: revocations,
		invalidator: invalidator,
		clock:       clk,
		logger:      logger,
	}
}

// Revoke kills the key identified by thumbprint for subdomain: it records the
// thumbprint on the subdomain's public revocation list (the durable, security-critical
// fact, committed first), then destroys the private key material in Vault, then
// invalidates the cached documents so the directory drops the key and the revocation
// list gains it.
//
// The ordering is deliberate. The list write is what makes every verifier reject the
// key within one poll interval; it MUST land even if the Vault destroy fails — Vault
// could be the very thing that is down during an incident, and destroying our copy is
// useless anyway if the private key was already exfiltrated. So the destroy is
// best-effort: a failure is logged and left for the scheduler's prune pass or a re-run,
// never returned. The whole operation is idempotent — an already-revoked key is still
// "known", so a retry re-publishes and re-attempts the erase without error.
func (rv *Revoker) Revoke(ctx context.Context, subdomain, thumbprint string) error {
	if !keystore.ValidSubdomain(subdomain) {
		return fmt.Errorf("%w: %q", keystore.ErrInvalidSubdomain, subdomain)
	}
	known, err := rv.belongsToAgent(ctx, subdomain, thumbprint)
	if err != nil {
		return err
	}
	if !known {
		return fmt.Errorf("%w: %s/%s", ErrUnknownThumbprint, subdomain, thumbprint)
	}

	asOf, err := rv.revocations.Revoke(ctx, subdomain, thumbprint, rv.clock.Now().UnixNano())
	if err != nil {
		return fmt.Errorf("revoke %s/%s: %w", subdomain, thumbprint, err)
	}

	ref := keystore.Ref{Subdomain: subdomain, Thumbprint: thumbprint}
	if destroyErr := rv.keys.Destroy(ctx, ref); destroyErr != nil {
		// The key is already publicly revoked; a failed erase is a hygiene gap the
		// prune pass or a re-run closes, not a reason to fail a revocation that has
		// already taken effect for every verifier.
		rv.logger.ErrorContext(ctx, "identity.revoke.destroy_failed",
			"subdomain", subdomain, "thumbprint", thumbprint, "err", destroyErr.Error())
	}

	rv.invalidator.Invalidate(subdomain)
	rv.logger.InfoContext(ctx, "identity.revoke",
		"subdomain", subdomain, "thumbprint", thumbprint, "as_of", asOf)
	return nil
}

// belongsToAgent reports whether thumbprint is a key this agent holds or has already
// revoked. A currently-held key is the ordinary case; an already-revoked one keeps a
// re-run idempotent (the first run's Destroy removed it from the held set). Anything
// else is an operator naming a key that was never this agent's — rejected before it
// can put a junk entry on the list.
//
// The held-key check is a Vault read, and Vault is exactly what may be down during the
// incident that prompts a revocation. So a Vault-UNAVAILABLE error does NOT abort: the
// typo guard degrades to trusting the operator (the CLI is already the authorization
// boundary, and a mistyped thumbprint on the list is harmless — it "revokes" a key no
// verifier holds), so Revoke's durable list write still lands. Postgres being down is
// still caught, by that write itself. Any other Vault fault (denied, corrupt) is a real
// failure and is returned.
func (rv *Revoker) belongsToAgent(ctx context.Context, subdomain, thumbprint string) (bool, error) {
	keys, err := rv.keys.List(ctx, subdomain)
	switch {
	case err == nil:
		for _, k := range keys {
			if k.Ref.Thumbprint == thumbprint {
				return true, nil
			}
		}
	case errors.Is(err, keystore.ErrUnavailable):
		return true, nil // Vault down — trust the operator so the revocation still lands
	default:
		return false, fmt.Errorf("list keys of %q: %w", subdomain, err)
	}
	_, revoked, err := rv.revocations.BySubdomain(ctx, subdomain)
	if err != nil {
		return false, fmt.Errorf("get revocation of %q: %w", subdomain, err)
	}
	return slices.Contains(revoked, thumbprint), nil
}
