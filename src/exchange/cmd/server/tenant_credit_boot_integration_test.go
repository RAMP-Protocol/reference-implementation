//go:build integration

package main

import (
	"context"
	"io"
	"log/slog"
	"math/big"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgtype"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
)

// Boot-time seeding of tenants.default_agent_credit from
// EXCHANGE_DEFAULT_AGENT_CREDIT. This package has a handful of DB-touching
// tests, so the per-test Postgres helper is the sanctioned setup shape.

// creditBootFixture is one migrated Postgres with a seeded default tenant.
type creditBootFixture struct {
	ctx      context.Context
	tenants  repo.TenantReadRepo
	audit    repo.AuditRepo
	tenantID string
	domain   string
	run      func() error // bootTenantConfig under the current env
}

func newCreditBootFixture(t *testing.T) *creditBootFixture {
	t.Helper()
	ctx := context.Background()
	dsn := sharedb.StartPostgres(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	pool, err := sharedb.Setup(ctx, sharedb.SetupOptions{
		DSN:             dsn,
		Migrations:      exchangedb.Migrations,
		MigrationsDir:   exchangedb.MigrationsDir,
		MigrationsTable: exchangedb.MigrationsTable,
	}, logger)
	if err != nil {
		t.Fatalf("db setup: %v", err)
	}
	t.Cleanup(pool.Close)

	const domain = "credit-boot.example"
	t.Setenv("EXCHANGE_DEFAULT_TENANT", domain)
	queries := sqlc.New(pool)
	// The tenant seed below writes through raw sqlc. The Testing Doctrine
	// forbids that in an arrange path, and this is an open violation, not a
	// sanctioned pattern: no repository port inserts tenants.
	//
	// It is held open rather than fixed because no production code inserts
	// tenants either — they are provisioned by operator SQL — so a repository
	// insert port would be production surface that exists only for tests. Many
	// arrange sites across the tree share this shape; converting them together,
	// behind a real tenant-provisioning surface, is filed as its own task.
	if _, err := queries.InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID:        "t_credit_boot",
		Domain:          domain,
		Ed25519KeyRef:   "secret://ed25519/t_credit_boot",
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
		RsaKeyRef:       pgtype.Text{},
	}); err != nil {
		t.Fatalf("insert tenant: %v", err)
	}
	return &creditBootFixture{
		ctx:      ctx,
		tenants:  repo.NewTenantReadRepo(queries),
		audit:    repo.NewAuditRepo(queries),
		tenantID: "t_credit_boot", domain: domain,
		// Bind to bootTenantConfig — the exact boot step main.go calls — so
		// removing the credit application from the boot path fails these tests,
		// not just a direct call one layer below it.
		run: func() error { return bootTenantConfig(ctx, logger, pool, queries) },
	}
}

// creditAuditRows reads the tenant's audit-log entries back through the
// production AuditRepo read surface — the documented path for integration
// side-effect assertions on the admin plane.
func (f *creditBootFixture) creditAuditRows(t *testing.T) []repo.AuditRecord {
	t.Helper()
	rows, err := f.audit.ByTenant(f.ctx, f.tenantID)
	if err != nil {
		t.Fatalf("read audit log back: %v", err)
	}
	return rows
}

// storedCredit reads the tenant's default_agent_credit back through the
// production repository surface.
func (f *creditBootFixture) storedCredit(t *testing.T) *big.Rat {
	t.Helper()
	tenant, err := f.tenants.ByDomain(f.ctx, f.domain)
	if err != nil {
		t.Fatalf("read tenant back: %v", err)
	}
	return tenant.DefaultAgentCredit
}

// TestApplyDefaultAgentCredit_SeedsAndOverwrites: a set variable lands on the
// default tenant's column; a later boot with a different value replaces it
// (full replace, last boot wins); an unset variable resets the column to 0 —
// the variable is the sole owner of the column, so removing it disables the
// grant on the next restart. Every boot's write commits together with one
// audit row attributed to the boot actor.
func TestApplyDefaultAgentCredit_SeedsAndOverwrites(t *testing.T) {
	f := newCreditBootFixture(t)

	t.Setenv(envDefaultAgentCredit, "100")
	if err := f.run(); err != nil {
		t.Fatalf("apply(100): %v", err)
	}
	if got := f.storedCredit(t); got.Cmp(testutil.MustRat(t, "100")) != 0 {
		t.Fatalf("stored credit = %s, want 100", got.RatString())
	}
	rows := f.creditAuditRows(t)
	if len(rows) != 1 {
		t.Fatalf("audit rows after first apply = %d, want 1", len(rows))
	}
	if rows[0].Action != "SetDefaultAgentCredit" {
		t.Fatalf("audit action = %q, want SetDefaultAgentCredit", rows[0].Action)
	}
	if rows[0].Actor == nil || *rows[0].Actor != "exchange-boot" {
		t.Fatalf("audit actor = %v, want exchange-boot", rows[0].Actor)
	}
	if detail := string(rows[0].Detail); !strings.Contains(detail, "100.00000000") {
		t.Fatalf("audit detail %q does not record the applied amount", detail)
	}

	t.Setenv(envDefaultAgentCredit, "12.5")
	if err := f.run(); err != nil {
		t.Fatalf("apply(12.5): %v", err)
	}
	if got := f.storedCredit(t); got.Cmp(testutil.MustRat(t, "12.5")) != 0 {
		t.Fatalf("stored credit = %s, want 12.5", got.RatString())
	}
	if rows := f.creditAuditRows(t); len(rows) != 2 {
		t.Fatalf("audit rows after second apply = %d, want 2", len(rows))
	}

	t.Setenv(envDefaultAgentCredit, "")
	if err := f.run(); err != nil {
		t.Fatalf("apply(unset): %v", err)
	}
	if got := f.storedCredit(t); got.Sign() != 0 {
		t.Fatalf("stored credit after unset boot = %s, want 0 (grant disabled)", got.RatString())
	}
	if rows := f.creditAuditRows(t); len(rows) != 3 {
		t.Fatalf("audit rows after unset boot = %d, want 3 (the reset to 0 is audited too)", len(rows))
	}
}

// TestApplyDefaultAgentCredit_RejectsMalformedValues: a value that is not a
// plain decimal (digits with an optional fraction), or one finer than ledger
// asset scale 8, fails the boot step and writes nothing — bad configuration
// surfaces loudly instead of rounding or silently disabling. The non-plain
// shapes big.Rat.SetString would happily parse (exponent, fraction, hex float,
// digit separator) are pinned as rejected.
func TestApplyDefaultAgentCredit_RejectsMalformedValues(t *testing.T) {
	f := newCreditBootFixture(t)
	for name, raw := range map[string]string{
		"not a decimal":      "ten",
		"negative":           "-5",
		"finer than scale 8": "0.000000001",
		"exponent":           "1e9",
		"rational fraction":  "5/2",
		"hex float":          "0x10p2",
		"digit separator":    "1_000",
	} {
		t.Setenv(envDefaultAgentCredit, raw)
		if err := f.run(); err == nil {
			t.Errorf("%s (%q): expected boot to fail", name, raw)
		}
	}
	if got := f.storedCredit(t); got.Sign() != 0 {
		t.Fatalf("stored credit = %s, want 0 (nothing written)", got.RatString())
	}
	if rows := f.creditAuditRows(t); len(rows) != 0 {
		t.Fatalf("audit rows after rejected values = %d, want 0 (rollback drops the audit row too)", len(rows))
	}
}

// TestApplyDefaultAgentCredit_MissingTenantWarnsAndSkips: an unseeded default
// tenant does not fail boot (mirroring warnIfDefaultTenantMissing) — the value
// is simply not applied.
func TestApplyDefaultAgentCredit_MissingTenantWarnsAndSkips(t *testing.T) {
	f := newCreditBootFixture(t)
	t.Setenv("EXCHANGE_DEFAULT_TENANT", "never-seeded.example")
	t.Setenv(envDefaultAgentCredit, "100")
	if err := f.run(); err != nil {
		t.Fatalf("apply with missing tenant must warn, not fail: %v", err)
	}
	// The seeded tenant (a different domain) is untouched, and nothing is audited.
	if got := f.storedCredit(t); got.Sign() != 0 {
		t.Fatalf("stored credit = %s, want 0 (nothing written)", got.RatString())
	}
	if rows := f.creditAuditRows(t); len(rows) != 0 {
		t.Fatalf("audit rows after skipped apply = %d, want 0", len(rows))
	}
}
