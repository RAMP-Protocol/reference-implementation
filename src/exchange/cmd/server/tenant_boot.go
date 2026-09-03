package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/big"
	"regexp"

	"github.com/jackc/pgx/v5/pgxpool"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/money"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// defaultTenantDomain resolves the single default tenant's domain the Register
// flow reads its activation policy from: EXCHANGE_DEFAULT_TENANT, falling back to
// EXCHANGE_DOMAIN when the operator's tenant domain and the Exchange domain
// coincide (ADR-021 §5 decision 1).
func defaultTenantDomain() string {
	return runhttp.EnvOr("EXCHANGE_DEFAULT_TENANT", exchangeDomain())
}

// bootTenantConfig runs the default-tenant boot steps: surface a missing
// default tenant early (warns and continues — a deployment may seed tenants
// after the process starts) and apply the EXCHANGE_DEFAULT_AGENT_CREDIT
// configuration (unset means 0), whose malformed values fail boot.
func bootTenantConfig(
	ctx context.Context, logger *slog.Logger, pool *pgxpool.Pool, queries *sqlc.Queries,
) error {
	warnIfDefaultTenantMissing(ctx, logger, repo.NewTenantReadRepo(queries))
	return applyDefaultAgentCredit(ctx, logger, pool, queries)
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

// envDefaultAgentCredit sets tenants.default_agent_credit for the default
// tenant at boot — the SOLE configuration channel for the welcome credit (the
// ADR-009 amendment of 2026-08-13). There is no admin RPC and operator SQL is
// not a supported channel: every boot replaces the column with this variable's
// value, and unset (or empty) means 0, so removing the variable disables the
// grant at the next restart.
const envDefaultAgentCredit = "EXCHANGE_DEFAULT_AGENT_CREDIT"

// decimalCreditPattern pins the accepted shape to a plain decimal — digits with
// an optional fraction. big.Rat.SetString alone would also accept exponents
// ("1e9"), fractions ("5/2"), hex floats ("0x10p2") and digit separators
// ("1_000"); none of those belong in a money knob, so the shape is checked
// before parsing.
var decimalCreditPattern = regexp.MustCompile(`^[0-9]+(\.[0-9]+)?$`)

// applyDefaultAgentCredit replaces the default tenant's default_agent_credit
// column with EXCHANGE_DEFAULT_AGENT_CREDIT at boot; unset or empty means 0,
// so the variable is the sole owner of the column and removing it disables the
// grant on the next restart. A malformed value — not a plain decimal, or finer
// than ledger asset scale 8 (the repo guard owns those bounds) — FAILS boot:
// bad configuration must surface loudly, the same stance as a misconfigured
// TigerBeetle. A default tenant that is not seeded yet only warns, mirroring
// warnIfDefaultTenantMissing: seed the tenant, then restart to apply the
// credit. The write routes through AdminService.SetDefaultAgentCredit so it
// commits together with its audit row, like every other write on the tenant
// admin plane.
func applyDefaultAgentCredit(
	ctx context.Context, logger *slog.Logger, pool *pgxpool.Pool, queries *sqlc.Queries,
) error {
	raw := runhttp.EnvOr(envDefaultAgentCredit, "0")
	if !decimalCreditPattern.MatchString(raw) {
		return fmt.Errorf("%s %q is not a plain decimal amount (digits with an optional fraction)",
			envDefaultAgentCredit, raw)
	}
	credit, ok := new(big.Rat).SetString(raw)
	if !ok {
		return fmt.Errorf("%s %q is not a decimal amount", envDefaultAgentCredit, raw)
	}
	domain := defaultTenantDomain()
	tenant, err := repo.NewTenantReadRepo(queries).ByDomain(ctx, domain)
	if errors.Is(err, repo.ErrTenantNotFound) {
		logger.Warn("default tenant not seeded yet — default agent credit NOT applied; "+
			"restart after seeding to apply it",
			"default_tenant_domain", domain, "default_agent_credit", raw)
		return nil
	}
	if err != nil {
		return fmt.Errorf("resolve default tenant for %s: %w", envDefaultAgentCredit, err)
	}
	admin := service.NewAdminServiceFromPool(pool, queries)
	if err := admin.SetDefaultAgentCredit(ctx, bootAdminCaller(), tenant.ID, credit); err != nil {
		return fmt.Errorf("apply %s: %w", envDefaultAgentCredit, err)
	}
	logger.Info("applied default agent credit to the default tenant",
		"default_tenant_domain", domain,
		"default_agent_credit", money.DecimalString(credit))
	return nil
}

// bootAdminCaller is the audit attribution for boot-time admin writes: there is
// no network peer and no request, so the process itself is named as the actor.
func bootAdminCaller() service.AdminCaller {
	actor := "exchange-boot"
	return service.AdminCaller{SourceAddr: "boot", Actor: &actor}
}
