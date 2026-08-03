package signup

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oidcup"
)

// KeyMinter is the subset of the keystore sign-up needs: mint the agent's first key
// and check whether it already holds one, so re-entry is idempotent.
type KeyMinter interface {
	Create(ctx context.Context, subdomain string, w keystore.Window) (keystore.Key, error)
	List(ctx context.Context, subdomain string) ([]keystore.Key, error)
}

// CardWriter persists the agent's Signature Agent Card.
type CardWriter interface {
	Upsert(ctx context.Context, subdomain string, card directory.Card) (directory.Card, error)
}

// Invalidator drops a subdomain's cached documents so a freshly-minted key or card
// shows up at once (same-process fast path; another process picks it up within the
// directory TTL).
type Invalidator interface {
	Invalidate(subdomain string)
}

const (
	defaultKeyLifetime = 365 * 24 * time.Hour
	maxSlugAttempts    = 8
)

// Config wires a Service. Keys/Cards/Developers/Slugs/Invalidator/Clock are required;
// KeyLifetime defaults to a year when unset (this service does not run a rotation
// scheduler, so the first key simply carries a long window).
type Config struct {
	Keys        KeyMinter
	Cards       CardWriter
	Developers  account.Store
	Slugs       SlugGen
	Invalidator Invalidator
	Clock       clock.Clock
	BaseDomain  string
	KeyLifetime time.Duration
}

// Service performs developer sign-up: provisioning at sign-in and the mandatory
// form's validation and storage.
type Service struct {
	cfg Config
}

// New validates the config and constructs a Service.
func New(cfg Config) (*Service, error) {
	switch {
	case cfg.Keys == nil || cfg.Cards == nil || cfg.Developers == nil:
		return nil, errors.New("signup: Keys, Cards, and Developers are required")
	case cfg.Slugs == nil || cfg.Invalidator == nil || cfg.Clock == nil:
		return nil, errors.New("signup: Slugs, Invalidator, and Clock are required")
	case cfg.BaseDomain == "":
		return nil, errors.New("signup: BaseDomain is required")
	}
	if cfg.KeyLifetime <= 0 {
		cfg.KeyLifetime = defaultKeyLifetime
	}
	return &Service{cfg: cfg}, nil
}

// SignIn provisions (or re-confirms) the agent identity for an authenticated
// developer and reports whether the mandatory form still needs filling. It is
// idempotent: a returning developer keeps the same subdomain, and a re-entry after a
// mid-way crash finishes the missing steps. It mirrors the multi-backend, no-tx
// order the Exchange's Register uses — the reserved account row is the durable
// anchor, then the Vault key, then the card; every step is safe to replay.
func (s *Service) SignIn(ctx context.Context, claims oidcup.Claims) (subdomain string, needsForm bool, err error) {
	dev, err := s.resolveOrReserve(ctx, claims)
	if err != nil {
		return "", false, err
	}
	if err := s.ensureKey(ctx, dev.Subdomain); err != nil {
		return "", false, err
	}
	if err := s.ensureCard(ctx, dev.Subdomain, claims); err != nil {
		return "", false, err
	}
	s.cfg.Invalidator.Invalidate(dev.Subdomain)
	return dev.Subdomain, !dev.RegistrationComplete, nil
}

// resolveOrReserve returns the developer's existing account or reserves a new one.
func (s *Service) resolveOrReserve(ctx context.Context, claims oidcup.Claims) (account.Developer, error) {
	dev, err := s.cfg.Developers.BySubject(ctx, claims.Issuer, claims.Subject)
	switch {
	case err == nil:
		return dev, nil
	case errors.Is(err, account.ErrNotFound):
		return s.reserve(ctx, claims)
	default:
		return account.Developer{}, fmt.Errorf("signup: look up developer: %w", err)
	}
}

// reserve mints subdomains until one is free — or until a concurrent sign-in turns
// out to have already created this identity's account, in which case that row wins.
func (s *Service) reserve(ctx context.Context, claims oidcup.Claims) (account.Developer, error) {
	for attempt := 0; attempt < maxSlugAttempts; attempt++ {
		slug, err := s.cfg.Slugs.New()
		if err != nil {
			return account.Developer{}, fmt.Errorf("signup: mint slug: %w", err)
		}
		dev, err := s.cfg.Developers.Reserve(ctx, account.Developer{
			Issuer:    claims.Issuer,
			Subject:   claims.Subject,
			Email:     claims.Email,
			Subdomain: slug + "." + s.cfg.BaseDomain,
		})
		switch {
		case err == nil:
			return dev, nil
		case errors.Is(err, account.ErrSubdomainTaken):
			continue
		case errors.Is(err, account.ErrAlreadyExists):
			return s.cfg.Developers.BySubject(ctx, claims.Issuer, claims.Subject)
		default:
			return account.Developer{}, fmt.Errorf("signup: reserve subdomain: %w", err)
		}
	}
	return account.Developer{}, ErrSlugExhausted
}

// ensureKey mints the agent's first signing key when it holds none. A returning
// developer keeps its existing key — sign-up does not rotate here.
func (s *Service) ensureKey(ctx context.Context, subdomain string) error {
	keys, err := s.cfg.Keys.List(ctx, subdomain)
	if err != nil {
		return fmt.Errorf("signup: list keys: %w", err)
	}
	if len(keys) > 0 {
		return nil
	}
	now := s.cfg.Clock.Now()
	if _, err := s.cfg.Keys.Create(ctx, subdomain, keystore.Window{
		NotBefore: now,
		NotAfter:  now.Add(s.cfg.KeyLifetime),
	}); err != nil {
		return fmt.Errorf("signup: create key: %w", err)
	}
	return nil
}

// ensureCard writes the agent's Signature Agent Card from the sign-in claims. Upsert
// is idempotent, so a returning developer's card is refreshed, not duplicated.
func (s *Service) ensureCard(ctx context.Context, subdomain string, claims oidcup.Claims) error {
	if _, err := s.cfg.Cards.Upsert(ctx, subdomain, cardFromClaims(subdomain, claims)); err != nil {
		return fmt.Errorf("signup: write card: %w", err)
	}
	return nil
}

// CompleteRegistration validates the form and, on success, stores the three
// licensing fields and flips the account to registration-complete. A non-nil
// *ValidationError means the form must re-render with no state changed; a returned
// error is a store fault. Provisioning already happened at SignIn — this records
// only the licensing data the form gates on.
func (s *Service) CompleteRegistration(
	ctx context.Context, issuer, subject string, in FormInput,
) (account.Developer, *ValidationError, error) {
	clean, verr := ValidateForm(in)
	if verr != nil {
		return account.Developer{}, verr, nil
	}
	dev, err := s.cfg.Developers.CompleteRegistration(ctx, issuer, subject, account.LicensingDetails{
		LegalEntity:         clean.LegalEntity,
		Address:             clean.Address,
		JurisdictionCountry: clean.JurisdictionCountry,
	})
	if err != nil {
		return account.Developer{}, nil, fmt.Errorf("signup: complete registration: %w", err)
	}
	return dev, nil, nil
}

// cardFromClaims derives the public card from the sign-in identity. The agent's own
// subdomain is its client_uri; the verified email becomes a mailto contact; purpose
// stays empty — a form-only sign-up asserts no intended use.
func cardFromClaims(subdomain string, claims oidcup.Claims) directory.Card {
	card := directory.Card{
		ClientName: displayName(claims, subdomain),
		ClientURI:  "https://" + subdomain,
	}
	if claims.Email != "" {
		card.Contacts = []string{"mailto:" + claims.Email}
	}
	return card
}

// displayName falls back from the OIDC display name to the email local-part to the
// subdomain, so the card always carries a non-empty client_name.
func displayName(claims oidcup.Claims, subdomain string) string {
	if claims.Name != "" {
		return claims.Name
	}
	if claims.Email != "" {
		if at := strings.IndexByte(claims.Email, '@'); at > 0 {
			return claims.Email[:at]
		}
		return claims.Email
	}
	return subdomain
}
