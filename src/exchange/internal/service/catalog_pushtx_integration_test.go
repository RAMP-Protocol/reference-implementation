//go:build integration

package service_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"log/slog"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/jackc/pgx/v5"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// authorizeAllManifests authorizes any caller pushing for its own domain: Get
// returns a publisher manifest whose domain equals the requested host, so
// AuthorizesContributor(m, caller) is true when caller == host.
type authorizeAllManifests struct{}

func (authorizeAllManifests) Get(_ context.Context, host string) (*rampwellknown.Manifest, error) {
	return &rampwellknown.Manifest{
		Ver: rampwellknown.Version, Role: rampwellknown.RolePublisher, Domain: host,
	}, nil
}

// nopRegistry satisfies agentreg.Registry; PushResources never calls it (Gate 1,
// caller-signature, runs in the transport layer, not the service).
type nopRegistry struct{}

func (nopRegistry) LookupPublicKey(context.Context, string) (ed25519.PublicKey, error) {
	return nil, errors.New("not used")
}
func (nopRegistry) RegisterFromManifest(context.Context, string, string) error { return nil }

// failOnNthUpsertTx delegates real in-tx upserts but fails the nth call, so a
// prior committed-within-tx insert exists for the rollback to undo.
type failOnNthUpsertTx struct {
	repo.CatalogRepo
	failAt int
	calls  int
}

func (f *failOnNthUpsertTx) UpsertTx(
	ctx context.Context, tx pgx.Tx, e repo.CatalogEntry,
) (repo.CatalogEntry, error) {
	f.calls++
	if f.calls >= f.failAt {
		return repo.CatalogEntry{}, errors.New("injected upsert failure")
	}
	return f.CatalogRepo.UpsertTx(ctx, tx, e)
}

// TestPushResources_AtomicRollbackOnMidBatchFailure proves the accepted-entries
// upsert batch is transactional (Arch rule 7): when the second entry's upsert
// fails, the first entry's insert is rolled back and the catalog stays empty.
func TestPushResources_AtomicRollbackOnMidBatchFailure(t *testing.T) {
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

	if _, err := pool.Exec(ctx,
		`INSERT INTO ramp.tenants (tenant_id, domain, hmac_secret_ref, ed25519_key_ref)
		 VALUES ($1, $2, 'h', 'k')`,
		"t1", "pub.example"); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	realRepo := repo.NewCatalogRepo(sqlc.New(pool))
	failing := &failOnNthUpsertTx{CatalogRepo: realRepo, failAt: 2}
	svc := service.NewCatalogService(failing, nopRegistry{}, authorizeAllManifests{},
		sharedb.PoolRunner{Pool: pool})

	_, err = svc.PushResources(ctx, &rampv1.PushResourcesRequest{
		TenantId: "t1",
		CallerId: "pub.example",
		Entries: []*rampv1.ResourceEntry{
			{Domain: "pub.example", Path: "/a"},
			{Domain: "pub.example", Path: "/b"},
		},
	})
	if err == nil {
		t.Fatal("expected PushResources to fail on the injected mid-batch error")
	}

	all, err := realRepo.ListAll(ctx)
	if err != nil {
		t.Fatalf("ListAll: %v", err)
	}
	if len(all) != 0 {
		t.Fatalf("expected 0 catalog rows after rollback, got %d", len(all))
	}
}
