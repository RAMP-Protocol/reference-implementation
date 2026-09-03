package main

import (
	"context"
	"log/slog"
	"net/http"

	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/transport"
)

// serveExchangeAndAdmin runs the public Exchange listener and the separate
// internal admin listener under one signal-driven shutdown context. The admin
// plane is a distinct port (ADMIN_ADDR) so it can be bound to an internal
// interface and firewalled off the public ingress at deploy time; it
// is never mounted on the public mux.
func serveExchangeAndAdmin(
	ctx context.Context,
	logger *slog.Logger,
	pool *pgxpool.Pool,
	queries *sqlc.Queries,
	wrapped http.Handler,
	audience *rampaudience.Interceptor,
) error {
	adminHandler, err := buildAdminHandler(logger, pool, queries, audience)
	if err != nil {
		return err
	}
	return runhttp.ServeGroup(
		ctx, logger,
		runhttp.ServerSpec{Name: "exchange", Addr: runhttp.EnvOr("EXCHANGE_ADDR", ":8081"), Handler: wrapped},
		runhttp.ServerSpec{Name: "admin", Addr: runhttp.EnvOr("ADMIN_ADDR", ":8082"), Handler: adminHandler},
	)
}

// buildAdminHandler builds the AdminService from the pool and queries, then delegates
// the wire assembly — emit-unpopulated codec + bidirectional protovalidate interceptor,
// NO request-signing, RequestID (outermost) then IP-allowlist — to the shared
// transport.WrapAdminSurface, the single constructor this production path and the
// integration harness both call. The admin plane is deliberately NOT wrapped by
// WrapPublicSurface and NOT mounted through the connectserver verify seam: it has no
// verified signer; the network allowlist is the only gate (ADR-022).
func buildAdminHandler(
	logger *slog.Logger, pool *pgxpool.Pool, queries *sqlc.Queries, audience *rampaudience.Interceptor,
) (http.Handler, error) {
	adminSvc := service.NewAdminServiceFromPool(pool, queries)
	evidenceSvc := service.NewEvidenceReadService(queries)
	return transport.WrapAdminSurface(
		logger, adminSvc, evidenceSvc, runhttp.EnvOr("ADMIN_ALLOWED_CIDRS", ""), audience)
}
