// Package main is the Broker service entrypoint.
//
// The Broker receives agent requests (free-form queries or URIs), discovers
// candidate URLs (EXA), probes each domain for /.well-known/ramp.json, routes
// to the appropriate Exchange when a marketplace represents the publisher,
// and falls back to a bare-URL response otherwise.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"

	"github.com/postindustria-tech/ramp-protocol/gen/go/ramp/v1/rampv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
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
	signer, err := signing.LoadFromEnv(brokerDomain, brokerID)
	if err != nil {
		return fmt.Errorf("signer setup: %w", err)
	}

	marketRepo := repo.NewMarketplaceRepo(pool)
	logRepo := repo.NewSelectionLogRepo(pool)
	if err := bootstrapRegistry(ctx, marketRepo); err != nil {
		return fmt.Errorf("registry bootstrap: %w", err)
	}

	discovery := buildDiscoveryClient(logger)
	prober := probe.New(http.DefaultClient, redisCli, logger, probe.Options{
		Scheme: runhttp.EnvOr("RAMP_PROBE_SCHEME", "https"),
	})
	xpool := xclient.NewPool(nil)
	budgetSvc := budget.Select(redisCli, 0)
	routes := transport.NewTransactionRouteStore()

	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", healthz(pool))

	resolve := transport.NewResolveHandler(transport.Deps{
		Marketplaces: marketRepo,
		Log:          logRepo,
		Discovery:    discovery,
		Prober:       prober,
		Exchange:     xpool,
		Budget:       budgetSvc,
		Signer:       signer,
		Routes:       routes,
		Logger:       logger,
	})
	mux.Handle("POST /broker/v1/resolve", transport.RequestIDMiddleware(resolve))

	wk := transport.NewWellKnownHandler(signer, brokerID)
	mux.Handle("GET /.well-known/ramp-agent.json", wk)

	relay := transport.NewReportUsageHandler(routes, marketRepo, xpool, logger)
	path, relayHandler := rampv1connect.NewExchangeServiceHandler(relay)
	mux.Handle(path, transport.RequestIDMiddleware(relayHandler))

	// Launch refresher goroutine — fire-and-forget.
	refresher := registry.NewRefresher(marketRepo, nil, logger, 0)
	go refresher.Run(ctx)

	addr := runhttp.EnvOr("BROKER_ADDR", ":8082")
	runhttp.Serve("broker", addr, mux, logger)
	return nil
}

func bootstrapRegistry(ctx context.Context, m repo.MarketplaceRepo) error {
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
