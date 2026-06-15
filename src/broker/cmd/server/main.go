// Package main is the Broker service entrypoint.
//
// The Broker receives agent requests (free-form queries or URIs), discovers
// candidate URLs (EXA), probes each domain for /.well-known/ramp.json, routes
// to the appropriate Exchange when an exchange represents the publisher,
// and falls back to a bare-URL response otherwise.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/httpsig"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/budget"
	brokerdb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/exa"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/probe"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/rediscli"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/registry"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/signing"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/transport"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/xclient"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(logger); err != nil {
		logger.Error("broker exited with error", "err", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	ctx := context.Background()

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

	exchangeRepo := repo.NewExchangeRepo(pool)
	logRepo := repo.NewSelectionLogRepo(pool)
	if err := bootstrapRegistry(ctx, exchangeRepo); err != nil {
		return fmt.Errorf("registry bootstrap: %w", err)
	}

	discovery := buildDiscoveryClient(logger)
	// SSRF-guarded fetch client for publisher .well-known probes: a resolve
	// request carries a caller-influenced domain, so the probe must not be
	// steerable onto internal targets. RAMP_FETCH_INSECURE_ALLOW_PRIVATE permits
	// docker-internal hosts in the compose/e2e stack.
	guardedFetch := rampwellknown.NewGuardedClientFromEnv()
	prober := probe.New(guardedFetch, logger, probe.Options{
		Scheme: runhttp.EnvOr("RAMP_PROBE_SCHEME", "https"),
	})
	xpool, agentKeys, err := setupRelayAndKeys(logger)
	if err != nil {
		return err
	}
	budgetSvc := budget.Select(redisCli, 0, clock.System{})

	mux := buildBrokerMux(brokerMuxDeps{
		pool: pool,
		resolveDeps: transport.Deps{
			Exchanges: exchangeRepo,
			Log:       logRepo,
			Discovery: discovery,
			Prober:    prober,
			Exchange:  xpool,
			Budget:    budgetSvc,
			Signer:    signer,
			Clk:       clock.System{},
		},
		signer:    signer,
		brokerID:  brokerID,
		agentKeys: agentKeys,
	})

	// Launch refresher goroutine — fire-and-forget.
	refresher := registry.NewRefresher(exchangeRepo, nil, logger, 0)
	go refresher.Run(ctx)

	// Request-id is outermost so every route (resolve, well-known, invalidation)
	// echoes/sets X-Request-ID and carries request_id in context — the same shape
	// the Exchange applies at its mux root.
	wrapped := transport.RequestIDMiddleware(logger, wrapWithHTTPSig(mux, agentKeys, redisCli))

	addr := runhttp.EnvOr("BROKER_ADDR", ":8082")
	runhttp.Serve("broker", addr, wrapped, logger)
	return nil
}

// loadKeysIfConfigured seeds reg from the JWKS file at BROKER_KEYS_FILE
// (default deploy/broker/keys.json). A missing file is a warning in demo
// mode, not a fatal — tests boot without a file and register keys dynamically.
func loadKeysIfConfigured(reg *transport.KeyRegistry, logger *slog.Logger) error {
	path := runhttp.EnvOr("BROKER_KEYS_FILE", "deploy/broker/keys.json")
	_, statErr := os.Stat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		logger.Warn("ramp.json file absent; starting with empty registry", "path", path)
		return nil
	}
	if statErr != nil {
		return fmt.Errorf("ramp.json stat %s: %w", path, statErr)
	}
	if err := reg.LoadFile(path); err != nil {
		return fmt.Errorf("ramp.json load: %w", err)
	}
	logger.Info("ramp.json loaded", "path", path, "count", len(reg.Snapshot()))
	return nil
}

// setupRelayAndKeys builds the Broker's outbound xclient.Pool (wrapped in the
// relay signing transport when a key is present) and the inbound KeyRegistry
// (seeded from the shared ramp.json JWKS plus the relay pubkey, so downstream
// Exchange callers verifying broker-relay signatures find the kid).
func setupRelayAndKeys(logger *slog.Logger) (*xclient.Pool, *transport.KeyRegistry, error) {
	relayHTTP, relayKey, err := newRelayHTTPClient(logger)
	if err != nil {
		return nil, nil, fmt.Errorf("broker relay signing: %w", err)
	}
	agentKeys := transport.NewKeyRegistry()
	if err := loadKeysIfConfigured(agentKeys, logger); err != nil {
		return nil, nil, err
	}
	if relayKey != nil {
		agentKeys.PutPublicKey(relayKey.KID, relayKey.Private.Public().(ed25519.PublicKey))
	}
	return xclient.NewPool(relayHTTP), agentKeys, nil
}

// newRelayHTTPClient loads the broker-relay private key and builds an
// *http.Client whose transport stamps RFC 9421 Signature headers on every
// outbound Broker→Exchange call. When the key file is absent the returned
// client is a plain http.Client — callers hitting a signed Exchange will get
// 401 but the Broker will still boot (useful for local dev without bootstrap).
func newRelayHTTPClient(logger *slog.Logger) (*http.Client, *xclient.RelayKey, error) {
	path := runhttp.EnvOr("BROKER_RELAY_KEY_FILE", "deploy/broker/broker-key.json")
	_, statErr := os.Stat(path)
	if errors.Is(statErr, os.ErrNotExist) {
		logger.Warn("broker-relay key absent; outbound Exchange calls will be unsigned", "path", path)
		return &http.Client{Timeout: 10 * time.Second}, nil, nil
	}
	if statErr != nil {
		return nil, nil, fmt.Errorf("broker-relay stat %s: %w", path, statErr)
	}
	key, err := xclient.LoadRelayKey(path)
	if err != nil {
		return nil, nil, err
	}
	logger.Info("broker-relay signing enabled", "kid", key.KID)
	transport := xclient.NewSigningTransport(http.DefaultTransport, key, 30*time.Second, clock.System{})
	return &http.Client{Timeout: 10 * time.Second, Transport: transport}, key, nil
}

// brokerMuxDeps collects everything buildBrokerMux wires onto the HTTP
// surface; grouping them here keeps run() under the funlen cap without
// exceeding the per-function-arg limit.
type brokerMuxDeps struct {
	pool interface {
		Ping(ctx context.Context) error
	}
	resolveDeps transport.Deps
	signer      *signing.CoSigner
	brokerID    string
	agentKeys   *transport.KeyRegistry
}

// buildBrokerMux assembles the Broker's HTTP surface: healthz, /broker/v1/resolve,
// and the unified /.well-known/ramp.json route. The Exchange relay handler is
// removed in W3 (deletes ye6f-9 code); W4 will rewire callers to the canonical
// DiscoverResources/ExecuteTransaction/ReportUsage relay.
func buildBrokerMux(d brokerMuxDeps) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz(d.pool))
	resolve := transport.NewResolveHandler(d.resolveDeps)
	// Request-id correlation is applied once at the mux root in run() (see
	// wrapWithHTTPSig call site), so every route — resolve, well-known, and
	// invalidation — carries an X-Request-ID, matching the Exchange.
	mux.Handle("POST /broker/v1/resolve", resolve)
	// BROKER_INVALIDATION_URL is published in the manifest so the Exchange learns
	// where to poll revocations; BROKER_INVALIDATION_FILE is the operator's
	// revoked-kid lever served at the route below. Both unset → no revocation
	// channel (the manifest omits invalidation_url; the route serves empty).
	invURL := runhttp.EnvOr("BROKER_INVALIDATION_URL", "")
	wk, err := transport.NewWellKnown(transport.WellKnownConfig{
		Signer:          d.signer,
		BrokerID:        d.brokerID,
		Keys:            d.agentKeys,
		InvalidationURL: invURL,
	})
	if err != nil {
		panic(fmt.Sprintf("broker well-known manifest build failed: %v", err))
	}
	wk.RegisterRoutes(mux)
	mux.Handle("GET "+rampwellknown.InvalidationPath,
		transport.NewInvalidationHandler(runhttp.EnvOr("BROKER_INVALIDATION_FILE", "")))
	return mux
}

// wrapWithHTTPSig builds the RFC 9421 middleware stack around mux, using the
// in-memory ramp.json registry for resolution and (optionally) Redis for
// replay protection.
func wrapWithHTTPSig(
	mux http.Handler,
	reg *transport.KeyRegistry,
	redisCli *redis.Client,
) http.Handler {
	var replay httpsig.ReplayStore
	if redisCli != nil {
		replay = httpsig.NewRedisReplayStore(redisCli, "httpsig:broker:replay:")
	} else {
		replay = httpsig.NewMemoryReplayStore(nil)
	}
	resolver := httpsig.NewStaticResolver(reg.Snapshot())
	return httpsig.Middleware(resolver, replay, httpsig.InterceptorOptions{
		RequestPredicate: brokerSigRequestPredicate,
		OnError:          transport.LogHTTPSigReject,
	}, mux)
}

// brokerSigRequestPredicate decides whether a request must clear the
// static-resolver httpsig gate.
//
// Verified surfaces:
//   - /broker/v1/*  : agent-facing API; every call MUST be signed. The
//     handler additionally enforces verified keyID == req.AgentID so a
//     verified agent cannot impersonate another agent.
//   - /ramp.*       : upstream Exchange RPCs; verified when a
//     Signature-Input header is present.
//
// Unverified paths: healthz, /.well-known/* — public by design.
func brokerSigRequestPredicate(r *http.Request) bool {
	path := r.URL.Path
	if strings.HasPrefix(path, "/broker/v1/") {
		return true
	}
	if !strings.HasPrefix(path, "/ramp.") {
		return false
	}
	return r.Header.Get("Signature-Input") != ""
}

func bootstrapRegistry(ctx context.Context, m repo.ExchangeRepo) error {
	var raw []byte
	if path := runhttp.EnvOr("BROKER_REGISTRY_FILE", ""); path != "" {
		data, err := os.ReadFile(path) //nolint:gosec // operator-controlled path
		if err != nil {
			return err
		}
		raw = data
	} else {
		raw = registry.DefaultBootstrap
	}
	entries, err := registry.LoadFromReader(bytes.NewReader(raw))
	if err != nil {
		return err
	}
	return registry.Reconcile(ctx, m, entries)
}

func buildDiscoveryClient(logger *slog.Logger) exa.DiscoveryClient {
	apiKey := runhttp.EnvOr("EXA_API_KEY", "")
	if apiKey == "" {
		logger.Info("exa disabled: using empty static discovery client")
		return &exa.StaticClient{}
	}
	client, err := exa.NewClient(nil, apiKey, exa.Options{})
	if err != nil {
		logger.Warn("exa init failed, falling back to static client", "err", err)
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
