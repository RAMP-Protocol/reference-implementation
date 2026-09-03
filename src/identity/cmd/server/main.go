// Command server runs the Identity Service: one HTTP binary that serves every
// agent's Web Bot Auth directory and Signature Agent Card across the wildcard zone
// *.<IDENTITY_BASE_DOMAIN>, dispatched by the request Host. Keys are read from the
// Vault KeyStore; card metadata from Postgres. Discovery documents are public, so
// the only middleware is request-id correlation — there is no signature gate.
//
// The same binary always fronts developer sign-up — the OAuth authorization server,
// resource-owner consent, and identity provisioning. Sign-up is not optional: the
// service requires IDENTITY_AUTH_ISSUER and the IDENTITY_OIDC_* upstream
// credentials and refuses to start without them. A rotation scheduler runs
// alongside for the process lifetime, sharing the same publisher.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/app"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/idconfig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/lifecycle"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauthserver"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oidcup"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/publisher"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/session"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/token"
)

func main() {
	// `identity healthcheck` probes the local /healthz and exits — the
	// distroless image has no shell or curl, so the compose healthcheck
	// execs the service binary itself. Mirrors the Exchange and Broker.
	runhttp.MaybeHealthcheck("IDENTITY_ADDR", ":8083")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("identity.exit", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := idconfig.SetupDB(ctx, logger)
	if err != nil {
		return err
	}
	defer pool.Close()

	store, err := idconfig.NewKeyStore()
	if err != nil {
		return fmt.Errorf("keystore: %w", err)
	}

	auth, err := buildAuthConfig(ctx, logger)
	if err != nil {
		return fmt.Errorf("sign-up config: %w", err)
	}

	mcpCfg, err := buildMCPConfig()
	if err != nil {
		return fmt.Errorf("mcp config: %w", err)
	}

	handler, svc, err := app.Build(app.Config{
		Pool:            pool,
		Keys:            store,
		Logger:          logger,
		BaseDomain:      runhttp.EnvOr("IDENTITY_BASE_DOMAIN", "rampmcp.org"),
		DirectoryTTL:    runhttp.EnvDuration("IDENTITY_DIRECTORY_TTL", publisher.DefaultTTL),
		WellKnownScheme: runhttp.EnvOr("IDENTITY_WELLKNOWN_SCHEME", "https"),
		Health:          func(ctx context.Context) error { return db.Ping(ctx, pool) },
		Auth:            auth,
		MCP:             mcpCfg,
	})
	if err != nil {
		return fmt.Errorf("build server: %w", err)
	}

	// The rotation scheduler runs beside the server for the lifetime of the process,
	// minting overlapping replacement keys on a cadence and pruning retired ones; it
	// shares the publisher so a rotation is visible in the served documents at once.
	//
	// SINGLE-SCHEDULER ASSUMPTION: this runs one scheduler per replica with no leader
	// election, so scaling the (otherwise stateless) identity server to N replicas runs
	// N schedulers. Concurrent rotations of the same subdomain can double-mint — benign
	// and self-healing (every minted key is valid, the directory is key-capped, and the
	// prune pass reaps the extras), but wasteful. The MVP runs a single replica. Before
	// scaling out, gate rotateIfDue's mint behind a Postgres advisory lock keyed on the
	// subdomain (pg_advisory_xact_lock), or elect a single scheduler-owning replica.
	scheduler := lifecycle.NewScheduler(store, svc, clock.System{}, logger, lifecycle.SchedulerConfig{
		Period:   runhttp.EnvDuration("IDENTITY_ROTATION_PERIOD", lifecycle.DefaultPeriod),
		Overlap:  runhttp.EnvDuration("IDENTITY_ROTATION_OVERLAP", lifecycle.DefaultOverlap),
		Interval: runhttp.EnvDuration("IDENTITY_ROTATION_INTERVAL", lifecycle.DefaultInterval),
	})
	go scheduler.Run(ctx)

	runhttp.Serve("identity", runhttp.EnvOr("IDENTITY_ADDR", ":8083"), handler, logger)
	return nil
}

// buildMCPConfig assembles the RAMP adapter's config from the environment, or
// fails closed when it cannot.
//
// The adapter is MANDATORY: it is the identity service's agent-facing surface, so
// a deployment that could not wire it is not a complete service and must not come
// up. It needs the Broker named — there is no separate on/off flag and no default
// URL, because a default would point an agent's signed requests somewhere nobody
// chose. Leaving it unset is a configuration error that stops startup rather than
// silently disabling the adapter.
//
// There is NO Exchange setting, and that is the design rather than an omission.
// An account is per-Exchange, an agent names which one per call, and the endpoint
// comes from that Exchange's own manifest — so there is nothing here to point
// anywhere. A deployment that wants to limit which Exchanges are reachable sets
// the optional allowlist below; that is a policy, not an address.
func buildMCPConfig() (*app.MCPConfig, error) {
	// Read through EnvTrimmed, like the allowlist eighteen lines below. "Is this
	// variable set?" gets one answer per deployment: with EnvOr a value of spaces
	// passed the check below and the service came up with a whitespace Broker URL,
	// while the same mistake on the allowlist read as unset. One operator error,
	// two behaviours, and nothing in the configuration file to show the difference.
	broker := runhttp.EnvTrimmed("IDENTITY_MCP_BROKER_URL")
	if broker == "" {
		return nil, errors.New("IDENTITY_MCP_BROKER_URL is required")
	}
	itemBytes, callBytes, err := contentByteCaps()
	if err != nil {
		return nil, err
	}
	return &app.MCPConfig{
		BrokerURL: broker,
		// Optional, and empty is the normal answer: the deployment speaks to any
		// Exchange an agent names. Set it to confine the service to Exchanges the
		// operator has a relationship with. It is NOT a required replacement for
		// the Exchange URL this service used to be given — the point of the
		// account tools taking a target per call is that there is nothing left to
		// configure, and a policy an operator did not write is not one to invent.
		ExchangeAllowlist: runhttp.EnvTrimmed("IDENTITY_MCP_EXCHANGE_ALLOWLIST"),
		// Defaults to the scheme the agents' own directories are served on: the
		// two are the same deployment choice (https in production, http for a
		// local stack), and splitting them invites one to drift.
		WellKnownScheme: runhttp.EnvOr("IDENTITY_MCP_WELLKNOWN_SCHEME",
			runhttp.EnvOr("IDENTITY_WELLKNOWN_SCHEME", "https")),
		// Zero means "unset": the RAMP client applies its own defaults. Resolving
		// them here instead would make the adapter's defaulting dead code and put
		// the value's owner in two places.
		CallTimeout:  runhttp.EnvDuration("IDENTITY_MCP_CALL_TIMEOUT", 0),
		SignatureTTL: runhttp.EnvDuration("IDENTITY_MCP_SIGNATURE_TTL", 0),
		// The proof-of-possession lifetime is its OWN knob, not the RAMP signature
		// TTL reused. The delivery edge keeps no replay store, so this value is a
		// replay window rather than merely a signature lifetime, and an operator
		// raising the RAMP TTL for a slow peer must not widen it by accident.
		PoPTTL: runhttp.EnvDuration("IDENTITY_MCP_POP_TTL", 0),
		// Same convention for the content leg. These are separate knobs from the
		// RAMP ones above because a publisher's edge is not a RAMP peer: it serves
		// whole documents rather than small protocol messages, so the timeout an
		// operator wants there is not the one they want for a protocol call.
		FetchTimeout:    runhttp.EnvDuration("IDENTITY_MCP_FETCH_TIMEOUT", 0),
		MaxContentBytes: itemBytes,
		// Batch bounds. A per-item cap above the batch budget is refused at startup
		// by the MCP adapter rather than collapsing every batch to one item.
		CallContentTimeout:  runhttp.EnvDuration("IDENTITY_MCP_CALL_CONTENT_TIMEOUT", 0),
		MaxCallContentBytes: callBytes,
	}, nil
}

// Ceilings for the two content-size knobs. Far above any plausible document, low
// enough that a typo cannot ask the registry to buffer a disk into a single
// JSON-RPC frame. A value above the ceiling is clamped to it, never discarded —
// an operator asking for more than we allow means "give me the most you can", and
// answering that with the much smaller default would be a silent surprise.
const (
	maxItemBytesCeiling int64 = 1 << 30
	maxCallBytesCeiling int64 = 4 << 30
)

// contentByteCaps reads the per-item and per-call body caps.
//
// Zero means "unset" here as everywhere else in buildMCPConfig, which is why an
// explicit 0 is not honoured as "refuse all content": the consumer cannot tell
// that from absent. A value that is not a positive integer at all carries no
// intent to honour, so it fails startup — the rest of this function is fail-loud
// on malformed input and a silently-ignored cap is how an operator ends up
// believing a limit is in force that is not.
func contentByteCaps() (itemBytes, callBytes int64, err error) {
	itemBytes, ok := runhttp.EnvInt64("IDENTITY_MCP_MAX_CONTENT_BYTES", 0, maxItemBytesCeiling)
	if !ok {
		return 0, 0, errors.New("IDENTITY_MCP_MAX_CONTENT_BYTES must be a positive integer")
	}
	callBytes, ok = runhttp.EnvInt64("IDENTITY_MCP_MAX_CALL_CONTENT_BYTES", 0, maxCallBytesCeiling)
	if !ok {
		return 0, 0, errors.New("IDENTITY_MCP_MAX_CALL_CONTENT_BYTES must be a positive integer")
	}
	return itemBytes, callBytes, nil
}

// buildAuthConfig assembles the developer sign-up config from the environment.
// Sign-up is mandatory, so a missing upstream OIDC provider or auth issuer is a
// hard startup failure, not a silent downgrade.
func buildAuthConfig(ctx context.Context, logger *slog.Logger) (*app.AuthConfig, error) {
	issuer := runhttp.EnvOr("IDENTITY_OIDC_ISSUER", "")
	authIssuer := runhttp.EnvOr("IDENTITY_AUTH_ISSUER", "")
	// The OIDC client id/secret accept a "_FILE" companion so they can arrive as
	// a mounted secret file (Docker/Kubernetes secrets, and the e2e stack where
	// the provider mints them at boot) rather than only inline env.
	clientID, err := runhttp.EnvOrFile("IDENTITY_OIDC_CLIENT_ID")
	if err != nil {
		return nil, err
	}
	clientSecret, err := runhttp.EnvOrFile("IDENTITY_OIDC_CLIENT_SECRET")
	if err != nil {
		return nil, err
	}
	if issuer == "" || clientID == "" || clientSecret == "" || authIssuer == "" {
		return nil, errors.New(
			"developer sign-up requires IDENTITY_AUTH_ISSUER and IDENTITY_OIDC_ISSUER/CLIENT_ID/CLIENT_SECRET",
		)
	}
	up, err := oidcup.New(ctx, oidcup.Config{
		Issuer:       issuer,
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  authIssuer + oauthserver.CallbackPath,
		Scopes:       strings.Fields(runhttp.EnvOr("IDENTITY_OIDC_SCOPES", "")),
	})
	if err != nil {
		return nil, fmt.Errorf("oidc upstream: %w", err)
	}
	sessionKey, err := sessionKeyFromEnv(logger)
	if err != nil {
		return nil, err
	}
	tokens, err := tokenIssuerFromEnv(authIssuer, logger)
	if err != nil {
		return nil, err
	}
	return &app.AuthConfig{
		Issuer:        authIssuer,
		Upstream:      up,
		SessionKey:    sessionKey,
		Tokens:        tokens,
		SecureCookies: strings.HasPrefix(authIssuer, "https://"),
	}, nil
}

// sessionKeyFromEnv loads the 32-byte cookie-sealing key from IDENTITY_SESSION_KEY
// (base64). When unset it generates an ephemeral key and warns: the sign-up cookies
// are short-lived, so a restart only interrupts in-flight sign-ups — but a stable key
// shared across instances is required for a real multi-instance deployment.
func sessionKeyFromEnv(logger *slog.Logger) ([]byte, error) {
	if raw := runhttp.EnvOr("IDENTITY_SESSION_KEY", ""); raw != "" {
		key, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("IDENTITY_SESSION_KEY: %w", err)
		}
		if len(key) != session.KeyLen {
			return nil, fmt.Errorf("IDENTITY_SESSION_KEY must decode to %d bytes, got %d", session.KeyLen, len(key))
		}
		return key, nil
	}
	key := make([]byte, session.KeyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, fmt.Errorf("generate session key: %w", err)
	}
	logger.Warn("identity.signup.ephemeral_session_key",
		"detail", "IDENTITY_SESSION_KEY unset; generated an ephemeral key (in-flight sign-ups drop on restart)")
	return key, nil
}

// tokenIssuerFromEnv builds the access-token signer from IDENTITY_TOKEN_SIGNING_KEY
// (base64 Ed25519 seed). When unset it generates an ephemeral key and warns.
//
// The MCP endpoint now verifies these tokens with this same issuer, so an
// ephemeral key no longer merely risks a future problem: every token minted before
// a restart stops verifying after it, and every signed-in agent is logged out.
// Set the key in any deployment that is not a throwaway.
//
// The audience is what tokens are scoped to AND what the MCP endpoint advertises
// as its protected-resource identifier, so the two cannot disagree.
func tokenIssuerFromEnv(authIssuer string, logger *slog.Logger) (*token.Issuer, error) {
	audience := runhttp.EnvOr("IDENTITY_TOKEN_AUDIENCE", authIssuer)
	priv, err := tokenSigningKey(logger)
	if err != nil {
		return nil, err
	}
	return token.NewIssuer(priv, authIssuer, audience, clock.System{})
}

// tokenSigningKey resolves the Ed25519 signing key, generating an ephemeral one when
// IDENTITY_TOKEN_SIGNING_KEY is unset.
func tokenSigningKey(logger *slog.Logger) (ed25519.PrivateKey, error) {
	if raw := runhttp.EnvOr("IDENTITY_TOKEN_SIGNING_KEY", ""); raw != "" {
		seed, err := base64.StdEncoding.DecodeString(raw)
		if err != nil {
			return nil, fmt.Errorf("IDENTITY_TOKEN_SIGNING_KEY: %w", err)
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("IDENTITY_TOKEN_SIGNING_KEY must decode to %d bytes, got %d", ed25519.SeedSize, len(seed))
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate token key: %w", err)
	}
	logger.Warn("identity.signup.ephemeral_token_key",
		"detail", "IDENTITY_TOKEN_SIGNING_KEY unset; generated an ephemeral key (issued tokens invalid after restart)")
	return priv, nil
}
