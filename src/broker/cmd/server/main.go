// Package main is the Broker service entrypoint.
//
// The Broker receives agent requests (free-form queries or URIs), discovers
// candidate URLs (EXA), probes each domain for /.well-known/ramp.json, routes
// to the appropriate Exchange when an exchange represents the publisher,
// and falls back to a bare-URL response otherwise.
package main

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
	"github.com/redis/go-redis/v9"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentkeys"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/keypolicy"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/replay"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/budget"
	brokerdb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/exa"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/probe"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/rediscli"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/registry"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/resolve"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

func main() {
	// `broker healthcheck` probes the local /healthz and exits — the
	// distroless image has no shell or curl, so the compose healthcheck
	// execs the service binary itself.
	runhttp.MaybeHealthcheck("BROKER_ADDR", ":8082")
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("broker.exit", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	// Tie the lifecycle context to the process shutdown signals so background
	// goroutines started on it (the per-agent WBA revocation poller and the
	// registry refresher) stop on shutdown instead of leaking. runhttp.Serve
	// installs its own signal handler for HTTP drain; both registrations receive
	// the signal.
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	pool, err := db.Setup(ctx, db.SetupOptions{
		DSN:             runhttp.EnvOr("BROKER_DSN", ""),
		Migrations:      brokerdb.Migrations,
		MigrationsDir:   brokerdb.MigrationsDir,
		MigrationsTable: brokerdb.MigrationsTable,
	}, logger)
	if err != nil {
		return fmt.Errorf("db setup: %w", err)
	}
	if pool == nil {
		return errors.New("BROKER_DSN is required")
	}
	defer pool.Close()

	redisCli, err := rediscli.Setup(ctx, runhttp.EnvOr("REDIS_URL", ""), logger)
	if err != nil {
		return fmt.Errorf("redis setup: %w", err)
	}
	if redisCli != nil {
		defer func() { _ = redisCli.Close() }()
	}

	brokerID := runhttp.EnvOr("BROKER_ID", "broker-local")
	brokerDomain := runhttp.EnvOr("BROKER_DOMAIN", "broker.local")
	signer, err := signing.LoadFromEnv(brokerDomain, brokerID, clock.System{})
	if err != nil {
		return fmt.Errorf("signer setup: %w", err)
	}

	exchangeRepo, logRepo, err := setupRegistryRepos(ctx, pool, logger)
	if err != nil {
		return err
	}

	discovery := buildDiscoveryClient(logger)
	fetchWiring := buildFetchWiring(ctx, logger)
	xpool, agentKeys, err := setupRelayAndKeys(logger, brokerDomain)
	if err != nil {
		return err
	}
	budgetSvc := budget.Select(redisCli, 0, clock.System{})

	mux := buildBrokerMux(brokerMuxDeps{
		pool: pool,
		resolveDeps: resolve.Deps{
			Exchanges: exchangeRepo,
			Log:       logRepo,
			Discovery: discovery,
			Prober:    fetchWiring.prober,
			Exchange:  xpool,
			Budget:    budgetSvc,
			Signer:    signer,
			Endpoints: fetchWiring.endpoints,
			Clk:       clock.System{},
			Verifier:  fetchWiring.verifier,
		},
		signer:        signer,
		brokerID:      brokerID,
		agentKeys:     agentKeys,
		agentResolver: fetchWiring.agentResolver,
		redisCli:      redisCli,
	})

	// Launch refresher goroutine — fire-and-forget.
	refresher := registry.NewRefresher(exchangeRepo, nil, logger, 0)
	go refresher.Run(ctx)

	// Request-id is outermost so every route (healthz, well-known, relay) carries
	// request_id in context and echoes X-Request-ID on responses. The
	// BrokerService connectserver handler (mounted inside buildBrokerMux) adds its
	// own request-id layer outermost to the /ramp.v1.BrokerService subtree so that
	// subtree carries the id on the reject path too. Having it here as well means
	// ALL routes carry it, not just the BrokerService surface.
	wrapped := buildWrapped(logger, mux)

	addr := runhttp.EnvOr("BROKER_ADDR", ":8082")
	runhttp.Serve("broker", addr, wrapped, logger)
	return nil
}

// buildWrapped assembles the Broker's outermost HTTP middleware: the shared
// public-surface stack around the Broker's mux, with the deployment-shape
// switches read from the environment here at the composition root (see
// runhttp.PublicSurfaceOptionsFromEnv for the fail-closed opt-in rationale).
func buildWrapped(logger *slog.Logger, mux http.Handler) http.Handler {
	return transport.WrapPublicSurface(logger, mux, runhttp.PublicSurfaceOptionsFromEnv())
}

// loadKeysIfConfigured seeds reg from the JWKS file at BROKER_KEYS_FILE
// (default deploy/broker/keys.json). A missing file is a warning in demo
// mode, not a fatal — tests boot without a file and register keys dynamically.
func loadKeysIfConfigured(reg *transport.KeyRegistry, logger *slog.Logger) error {
	path := runhttp.EnvOr("BROKER_KEYS_FILE", "deploy/broker/keys.json")
	_, statErr := os.Stat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		logger.Warn("broker.registry.absent", "path", path)
		return nil
	}
	if statErr != nil {
		return fmt.Errorf("ramp.json stat %s: %w", path, statErr)
	}
	if err := reg.LoadFile(path); err != nil {
		return fmt.Errorf("ramp.json load: %w", err)
	}
	logger.Info("broker.registry.loaded", "path", path, "count", len(reg.Snapshot()))
	return nil
}

// setupRelayAndKeys builds the Broker's outbound xclient.Pool (wrapped in the
// relay signing transport when a key is present) and the inbound KeyRegistry
// (seeded from the shared ramp.json JWKS plus the relay pubkey, so downstream
// Exchange callers verifying broker-relay signatures find the kid).
func setupRelayAndKeys(logger *slog.Logger, brokerDomain string) (*xclient.Pool, *transport.KeyRegistry, error) {
	relayHTTP, relayKey, err := newRelayHTTPClient(logger, brokerDomain)
	if err != nil {
		return nil, nil, fmt.Errorf("broker relay signing: %w", err)
	}
	agentKeys := transport.NewKeyRegistry()
	if err := loadKeysIfConfigured(agentKeys, logger); err != nil {
		return nil, nil, err
	}
	if relayKey != nil {
		// After the WBA split the relay key is registered under its RFC 7638
		// thumbprint (derived by PutPublicKey), not a broker-prefixed kid.
		agentKeys.PutPublicKey(relayKey.Private.Public().(ed25519.PublicKey))
	}
	return xclient.NewPool(relayHTTP), agentKeys, nil
}

// newRelayHTTPClient loads the broker-relay private key and builds an
// *http.Client whose transport stamps RFC 9421 Signature headers on every
// outbound Broker→Exchange call. When the key file is absent the returned
// client is a plain http.Client — callers hitting a signed Exchange will get
// 401 but the Broker will still boot (useful for local dev without bootstrap).
func newRelayHTTPClient(logger *slog.Logger, brokerDomain string) (*http.Client, *xclient.RelayKey, error) {
	path := runhttp.EnvOr("BROKER_RELAY_KEY_FILE", "deploy/broker/broker-key.json")
	_, statErr := os.Stat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		logger.Warn("broker.relay.key_absent", "path", path)
		return &http.Client{Timeout: 10 * time.Second}, nil, nil
	}
	if statErr != nil {
		return nil, nil, fmt.Errorf("broker-relay stat %s: %w", path, statErr)
	}
	key, err := xclient.LoadRelayKey(path)
	if err != nil {
		return nil, nil, err
	}
	logger.Info("broker.relay.signing", "keyid", key.KeyID)
	transport, err := xclient.NewSigningTransport(http.DefaultTransport, key, brokerDomain, 30*time.Second, clock.System{})
	if err != nil {
		return nil, nil, fmt.Errorf("broker-relay signing transport: %w", err)
	}
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}, key, nil
}

// brokerMuxDeps collects everything buildBrokerMux wires onto the HTTP
// surface; grouping them here keeps run() under the funlen cap without
// exceeding the per-function-arg limit.
type brokerMuxDeps struct {
	pool interface {
		Ping(ctx context.Context) error
	}
	resolveDeps resolve.Deps
	signer      *signing.CoSigner
	brokerID    string
	agentKeys   *transport.KeyRegistry
	// agentResolver is the per-agent well-known fallback (nil when disabled).
	// Composed AFTER agentKeys so a bootstrap-file kid resolves without a fetch.
	agentResolver helpers.KeyResolver
	// redisCli backs the relay route's own replay store (Redis when present,
	// in-memory otherwise). The relay route is excluded from the connectserver
	// gate, so it enforces sig1 (keyid,signature) uniqueness itself.
	redisCli *redis.Client
}

// agentSig1Resolver composes the static agent-key registry with the per-agent
// well-known fallback (when enabled) for verifying an agent's sig1. Both
// agent-facing surfaces authenticate identically and MUST stay that way: the
// bespoke relay routes (which self-verify at the boundary) and the
// /ramp.v1.BrokerService connectserver verify gate both drive the SDK verifier
// with this one composite (static bootstrap kid first, then the well-known
// fallback for a never-seen agent). If a surface ever needs a genuinely
// different trust policy, encode it as an explicit parameter here rather than
// forking a second copy.
//
// Revocation is DELIBERATELY not enforced here: this composite carries no
// revocation-aware delegate against a revocation channel, so an agent kid the
// operator has revoked but which is still present in the static bootstrap
// registry verifies at the Broker. That is by design — the Broker only RELAYS
// (it never terminates a transaction: it holds no funds and binds no delivery
// URL), and every relayed request is re-verified downstream at the Exchange,
// which is the single authoritative revocation checkpoint. The Exchange fails
// CLOSED (it refuses to boot without EXCHANGE_BROKER_WELLKNOWN_URL) and its
// composite consults the Broker's revocation channel FIRST, rejecting a revoked
// thumbprint even when it is directory-absent (via the SDK revocation-set
// membership accessor) — so a revoked static-bootstrap key has a fail-closed
// checkpoint on the whole Agent→Broker→Exchange path. Duplicating that check at
// the Broker would need the Broker to CONSUME its own revocation channel
// (it currently only PUBLISHES one, via BROKER_REVOCATION_URL/_FILE, for the
// Exchange to poll) — added inbound revocation infra for no security gain, since
// the terminal checkpoint already covers this path. Should the Broker ever gain
// a terminal (non-relay) agent surface, a revocation-aware delegate belongs here
// FIRST, mirroring the Exchange's brokerRevocationResolver.
func (d brokerMuxDeps) agentSig1Resolver() helpers.KeyResolver {
	static := d.agentKeys.WindowedResolver(clock.System{})
	if d.agentResolver == nil {
		return static
	}
	return keypolicy.NewCompositeResolver(static, d.agentResolver)
}

// buildBrokerMux assembles the Broker's HTTP surface: healthz, the canonical
// ramp.v1.BrokerService Connect endpoint, the bespoke relay
// routes, and the unified /.well-known/ramp.json route.
func buildBrokerMux(d brokerMuxDeps) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz(d.pool))
	resolveHandler := resolve.NewService(d.resolveDeps)
	// ADR-019: the canonical ramp.v1.BrokerService/Resolve Connect
	// endpoint is the SOLE agent surface over the *Service business core
	// (the bespoke POST /broker/v1/resolve route was removed in the contract
	// cleanup). connectserver.NewBrokerServiceHandler wraps the generated handler
	// with request-id (outermost) → RFC 9421 verify middleware → connect
	// interceptors (protovalidate bidirectional). MaxSignatures is unset (0 =
	// unbounded): the hop bound is an Exchange-terminal policy; bounding it at the
	// Broker too would double-count the relay hop the Broker is about to add.
	// The resolver and replay store for the BrokerService surface are
	// constructed inline from the same agentKeys + agentResolver and redisCli
	// that the relay routes also draw from.
	brokerResolver := d.agentSig1Resolver()
	replayStore := replay.NewCoreAdapter(replay.NewStore(d.redisCli, "httpsig:broker:replay:"))
	svrOpts := []connectserver.ServerOption{
		connectserver.WithKeyResolver(brokerResolver),
		connectserver.WithReplayStore(replayStore),
		connectserver.WithValidation(connect.ValidationStrict),
		// Zero-valued response fields stay on the wire (platform JSON contract).
		connectserver.WithEmitUnpopulated(),
		// A /ramp. request must clear the seam iff it PRESENTS a signature: an
		// unsigned Resolve reaches the handler, which finds no verified context
		// and returns the typed Unauthenticated fault (ADR-019 error detail) —
		// the no-caller negative path the contract tests drive.
		connectserver.WithVerifyGate(func(r *http.Request) bool {
			return r.Header.Get("Signature-Input") != ""
		}),
		// Audit-log every gate rejection with its SDK-classified outcome
		// (replay / broken_chain / hop_budget / signature).
		connectserver.WithOnReject(transport.LogHTTPSigReject),
	}
	connectPath, connectHandler := connectserver.NewBrokerServiceHandler(
		transport.NewBrokerConnectHandler(resolveHandler), svrOpts...,
	)
	mux.Handle(connectPath, connectHandler)
	mountExchangeRelay(mux, d)
	mountDiscoverRelay(mux, d)
	// BROKER_REVOCATION_URL is advertised in the WBA directory as revocation_url so
	// the Exchange learns where to poll revocations; BROKER_REVOCATION_FILE is the
	// operator's revoked-thumbprint lever served at the route below. Both unset →
	// no revocation channel (the directory omits revocation_url; the route serves
	// the empty, nothing-revoked baseline).
	revURL := runhttp.EnvOr("BROKER_REVOCATION_URL", "")
	wk, err := transport.NewWellKnown(transport.WellKnownConfig{
		Signer:        d.signer,
		BrokerID:      d.brokerID,
		Keys:          d.agentKeys,
		RevocationURL: revURL,
	})
	if err != nil {
		panic(fmt.Sprintf("broker well-known manifest build failed: %v", err))
	}
	wk.RegisterRoutes(mux)
	mux.Handle("GET "+rampwellknown.RevocationPath,
		transport.NewRevocationHandler(runhttp.EnvOr("BROKER_REVOCATION_FILE", "")))
	return mux
}

// mountExchangeRelay registers the bespoke relay route
// POST /broker/v1/exchange/execute on the SAME mux as the Connect resolve
// handler. The route is deliberately NON-/ramp.-prefixed, so it sits outside
// the BrokerService connectserver verify gate. The relay handler self-verifies
// the agent's sig1 at the boundary (open-proxy guard) and enforces its OWN
// relay-scoped replay store. sig1 is verified by agentSig1Resolver — the
// static bootstrap kid first, then the per-agent well-known fallback (ADR-009
// D2) for a never-seen agent.

// mountExchangeRelay wires the bespoke relay route. Each request surface takes
// its own prefix-scoped replay.NewStore instance (a fresh store per call — the
// in-memory branch relies on that for isolation) so the execute, discover, and
// BrokerService surfaces never share a replay namespace.
func mountExchangeRelay(mux *http.ServeMux, d brokerMuxDeps) {
	resolver := d.agentSig1Resolver()
	replayStore := replay.NewStore(d.redisCli, "httpsig:broker:relay:execute:")
	// The relay resolves the signed Offer.exchange to the endpoint the Exchange
	// advertises in its own /.well-known/ramp.json through the SAME
	// shared resolver discovery uses (resolveDeps.Endpoints) — one guarded
	// instance, not a second inline build. The well-known GET is unsigned (the
	// relay's signing transport is not used) and the shared resolver carries the
	// env-guarded SSRF client, so a registered domain that rebinds to a private
	// address is refused at dial time, not merely string-checked by the handler's
	// pre-fetch GetByDomain trust gate.
	relay := transport.NewExchangeRelayHandler(
		d.resolveDeps.Exchange, resolver, d.resolveDeps.Endpoints, d.resolveDeps.Exchanges, clock.System{}, replayStore,
	)
	mux.Handle("POST /broker/v1/exchange/execute", relay)
}

// mountDiscoverRelay registers the bespoke known-URL discover-relay route
// POST /broker/v1/exchange/discover — the discovery counterpart of
// mountExchangeRelay. Like the execute relay it is deliberately NON-/ramp.-
// prefixed, so it sits outside the BrokerService connectserver verify gate.
// The handler self-verifies the agent's sig1 at the boundary (open-proxy guard)
// and enforces its OWN relay-scoped replay store under a DISTINCT key prefix
// ("httpsig:broker:relay:discover:") so a discover sig1 and an execute sig1
// occupy disjoint replay namespaces.
func mountDiscoverRelay(mux *http.ServeMux, d brokerMuxDeps) {
	resolver := d.agentSig1Resolver()
	replayStore := replay.NewStore(d.redisCli, "httpsig:broker:relay:discover:")
	relay := transport.NewDiscoverRelayHandler(
		d.resolveDeps.Exchange, resolver, d.resolveDeps.Exchanges, clock.System{}, replayStore,
	)
	mux.Handle("POST /broker/v1/exchange/discover", relay)
}

// buildAgentResolver builds the per-agent well-known transport-key resolver
// (ADR-009 D2): when an agent's kid is absent from the bootstrap keys file, it
// resolves the key from the agent's own /.well-known/ramp.json so a
// never-before-seen agent's sig1 verifies at the resolve gate and in the relay
// handler. Returns nil (resolution disabled) when BROKER_AGENT_WELLKNOWN_RESOLUTION
// is off; mirrors the Exchange-side resolver.
func buildAgentResolver(ctx context.Context, fetch *http.Client, logger *slog.Logger) helpers.KeyResolver {
	if !runhttp.EnvBool("BROKER_AGENT_WELLKNOWN_RESOLUTION", true) {
		return nil
	}
	logger.Info("broker.httpsig.wellknown")
	return agentkeys.NewFromEnv(ctx, fetch, logger)
}

// buildProbeWiring constructs the SSRF-guarded fetch client shared by the
// publisher .well-known probe and the per-agent WBA key resolver, then builds
// both. A resolve request carries a caller-influenced domain, so the probe must
// not be steerable onto internal targets; the guard is SDK-owned, constructed
// once here at the composition root from the SDK factory and injected. SKIP_SSRF
// permits docker-internal hosts and ALLOW_INSECURE permits plaintext http in the
// compose/e2e stack.
func buildProbeWiring(
	ctx context.Context, logger *slog.Logger,
) (*probe.Prober, helpers.KeyResolver) {
	guardedFetch := resolvers.NewGuardedClientFromEnv()
	prober := probe.New(guardedFetch, logger, probe.Options{
		Scheme: runhttp.EnvOr("RAMP_WELLKNOWN_SCHEME", "https"),
	})
	return prober, buildAgentResolver(ctx, guardedFetch, logger)
}

// bootstrapRegistry seeds broker.exchanges from the operator's registry file.
// With BROKER_REGISTRY_FILE unset it seeds nothing and the Broker routes to no
// Exchange until one is added — deliberately, so no deployment inherits example
// data it then has to clean out. The empty case returns BEFORE the decoder: a
// zero-byte YAML document decodes to io.EOF, which would fail the boot outright.
func bootstrapRegistry(ctx context.Context, m repo.ExchangeRepo, logger *slog.Logger) error {
	path := runhttp.EnvOr("BROKER_REGISTRY_FILE", "")
	if path == "" {
		logger.WarnContext(ctx, "broker.registry.no_bootstrap")
		return nil
	}
	entries, err := registry.LoadFromFile(path)
	if err != nil {
		return err
	}
	return registry.Reconcile(ctx, m, entries)
}

func buildDiscoveryClient(logger *slog.Logger) exa.DiscoveryClient {
	apiKey := runhttp.EnvOr("EXA_API_KEY", "")
	if apiKey == "" {
		logger.Info("broker.exa.disabled")
		return &exa.StaticClient{}
	}
	client, err := exa.NewClient(nil, apiKey, exa.Options{})
	if err != nil {
		logger.Warn("broker.exa.init_failed", "err", err)
		return &exa.StaticClient{}
	}
	return client
}

func healthz(pool interface {
	Ping(ctx context.Context) error
},
) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if pool != nil {
			if err := pool.Ping(r.Context()); err != nil {
				http.Error(w, "db unavailable", http.StatusServiceUnavailable)
				return
			}
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}
}
