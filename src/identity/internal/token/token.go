// Package token mints and verifies the access token the Identity Service issues at
// the end of a sign-in. The token is an EdDSA-signed JWT, audience-bound to the MCP
// server it will eventually authorize — asymmetric so that resource server can
// verify it from the public half without holding a shared secret. Nothing consumes
// the token yet (the MCP server is a later ticket), so today it is issued and its
// shape is asserted; Verify exists so the issuer is testable and the future
// resource server has a reference verifier.
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// ErrInvalid marks a token that failed signature, structure, or claim validation.
var ErrInvalid = errors.New("token: invalid")

// Issuer signs and verifies access tokens under one Ed25519 key.
type Issuer struct {
	signer   jose.Signer
	public   ed25519.PublicKey
	issuer   string
	audience string
	clk      clock.Clock
}

// NewIssuer builds an Issuer over an Ed25519 private key. issuer and audience are
// the `iss` and `aud` every minted token carries; audience names the MCP resource
// server the token is scoped to.
func NewIssuer(priv ed25519.PrivateKey, issuer, audience string, clk clock.Clock) (*Issuer, error) {
	if len(priv) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("token: private key must be %d bytes, got %d", ed25519.PrivateKeySize, len(priv))
	}
	if clk == nil {
		return nil, errors.New("token: clock is required")
	}
	signer, err := jose.NewSigner(
		jose.SigningKey{Algorithm: jose.EdDSA, Key: priv},
		(&jose.SignerOptions{}).WithType("JWT"),
	)
	if err != nil {
		return nil, fmt.Errorf("token: new signer: %w", err)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("token: deriving public key")
	}
	return &Issuer{signer: signer, public: pub, issuer: issuer, audience: audience, clk: clk}, nil
}

// Audience returns the value every minted token is audience-bound to — the
// resource server the token is scoped to. The MCP endpoint publishes it as its
// OAuth protected-resource identifier, so what a client is told to request a token
// for is read from the issuer itself and cannot drift from what tokens carry.
func (i *Issuer) Audience() string { return i.audience }

// Mint returns a signed JWT for subject, valid for ttl. subject is the developer's
// minted subdomain — the durable identity the token authenticates.
func (i *Issuer) Mint(subject string, ttl time.Duration) (string, error) {
	jti, err := randomID()
	if err != nil {
		return "", err
	}
	now := i.clk.Now()
	claims := jwt.Claims{
		Issuer:    i.issuer,
		Subject:   subject,
		Audience:  jwt.Audience{i.audience},
		IssuedAt:  jwt.NewNumericDate(now),
		Expiry:    jwt.NewNumericDate(now.Add(ttl)),
		NotBefore: jwt.NewNumericDate(now),
		ID:        jti,
	}
	raw, err := jwt.Signed(i.signer).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("token: sign: %w", err)
	}
	return raw, nil
}

// Verify checks the signature and validates iss/aud/exp against the clock, returning
// the claims on success or ErrInvalid otherwise.
func (i *Issuer) Verify(raw string) (jwt.Claims, error) {
	parsed, err := jwt.ParseSigned(raw, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		return jwt.Claims{}, ErrInvalid
	}
	var claims jwt.Claims
	if err := parsed.Claims(i.public, &claims); err != nil {
		return jwt.Claims{}, ErrInvalid
	}
	err = claims.Validate(jwt.Expected{
		Issuer:      i.issuer,
		AnyAudience: jwt.Audience{i.audience},
		Time:        i.clk.Now(),
	})
	if err != nil {
		return jwt.Claims{}, ErrInvalid
	}
	return claims, nil
}

// randomID mints a 128-bit base64url jti so two tokens minted in the same second
// are still distinct.
func randomID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("token: random id: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}
