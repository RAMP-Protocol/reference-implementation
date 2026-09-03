package publisher

import (
	"context"
	"errors"
	"fmt"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	wkserver "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/server"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
)

// Registrations is the narrow slice of the developer-account store the publisher
// needs: does this subdomain name a registered agent? *repo.PgxDeveloperRepo
// satisfies it. Only the read is taken, mirroring KeySource and
// directory.CardReader — the publisher never writes an account.
type Registrations interface {
	BySubdomain(ctx context.Context, subdomain string) (account.Developer, error)
}

// Manifest returns the RAMP commercial overlay for subdomain, or ErrAbsent when
// the subdomain names no registered agent and ErrUnavailable when the account
// store is down.
func (s *Service) Manifest(ctx context.Context, subdomain string) ([]byte, error) {
	return s.pick(ctx, subdomain, func(d *docSet) ([]byte, bool) { return d.manifest, d.manifestUnavail })
}

// buildManifest sets ds.manifest for a registered agent, or reports (unavailable)
// when the account store is down, or leaves it absent.
//
// The document itself is derivable — the role is always ROLE_AGENT and the domain is
// the subdomain being served — so nothing is read to BUILD it. The account row is read
// to decide whether to serve it at all, and it is the authoritative answer: sign-up
// reserves that row BEFORE minting the Vault key and writing the card, across three
// backends with no transaction spanning them, and it is designed to be replayed after a
// crash between those steps. So an agent's published documents are not a sound proxy
// for whether it is registered — a reserved account whose key never landed has none of
// them, and an orphaned key or card has no account behind it. Reading the row costs one
// query per cache build, not per request.
func (s *Service) buildManifest(ctx context.Context, subdomain string, ds *docSet) (bool, error) {
	_, err := s.registrations.BySubdomain(ctx, subdomain)
	switch {
	case err == nil:
		// Built through the shared library so the overlay this registry serves is
		// assembled, protocol-validated and marshalled exactly as every other RAMP
		// participant's is, and stamps the one manifest version constant.
		raw, buildErr := wkserver.Build(wkserver.Config{
			Role:   rampwellknown.RoleAgent,
			Domain: subdomain,
		})
		if buildErr != nil {
			return false, fmt.Errorf("publisher: manifest for %q: %w", subdomain, buildErr)
		}
		ds.manifest = raw
		return false, nil
	case errors.Is(err, account.ErrNotFound):
		return false, nil // not a registered agent — the overlay is absent (404)
	case errors.Is(err, account.ErrUnavailable):
		return true, nil // account store down — the overlay route 503s, its siblings do not
	default:
		return false, err
	}
}
