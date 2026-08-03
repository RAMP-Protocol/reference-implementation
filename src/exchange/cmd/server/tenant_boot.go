package main

import (
	"context"
	"errors"
	"log/slog"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// defaultTenantDomain resolves the single default tenant's domain the Register
// flow reads its activation policy from: EXCHANGE_DEFAULT_TENANT, falling back to
// EXCHANGE_DOMAIN when the operator's tenant domain and the Exchange domain
// coincide (ADR-021 §5 decision 1).
func defaultTenantDomain() string {
	return runhttp.EnvOr("EXCHANGE_DEFAULT_TENANT",
		runhttp.EnvOr("EXCHANGE_DOMAIN", "exchange.ramp.local"))
}

// warnIfDefaultTenantMissing probes the configured default tenant at boot and
// logs a clear warning if it is not seeded yet. It deliberately does NOT fail
// boot: a deployment may seed tenants after the process starts, and the first
// Register then succeeds. Without this probe an unseeded default tenant surfaces
// only as an error on the first Register; the warning makes the setup gap
// visible at startup instead.
func warnIfDefaultTenantMissing(ctx context.Context, logger *slog.Logger, tenants repo.TenantReadRepo) {
	domain := defaultTenantDomain()
	_, err := tenants.ByDomain(ctx, domain)
	switch {
	case err == nil:
		return
	case errors.Is(err, repo.ErrTenantNotFound):
		logger.Warn("default tenant not found yet — Register will fail until it is seeded",
			"default_tenant_domain", domain)
	default:
		logger.Warn("could not verify default tenant at boot",
			"default_tenant_domain", domain, "err", err)
	}
}
