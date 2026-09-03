//go:build integration

package service_test

import (
	"context"
	"crypto/ed25519"
	"errors"
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"github.com/jackc/pgx/v5"
	"google.golang.org/protobuf/types/known/structpb"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db/sqlc"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/repo"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service/servicetest"
)

// pushTestExchangeDomain is this test Exchange's own domain. The manifest stub
// attests resource_owner_id on an AuthorizedExchange entry for it, and the service
// is constructed with the same value, so the resource-owner gate accepts.
const pushTestExchangeDomain = "exchange.test"

// authorizeAllManifests authorizes any caller pushing for its own domain and
// attests a resource_owner_id for pushTestExchangeDomain: Get returns a publisher
// manifest whose domain equals the requested host (so AuthorizesContributor(m,
// caller) is true when caller == host) and which carries the payee attestation the
// resource-owner gate requires.
type authorizeAllManifests struct{}

func (authorizeAllManifests) Get(_ context.Context, host string) (*rampwellknown.Manifest, error) {
	ext, err := structpb.NewStruct(map[string]any{"resource_owner_id": "owner-" + host})
	if err != nil {
		return nil, err
	}
	return &rampwellknown.Manifest{
		Ver: rampwellknown.Version, Role: rampwellknown.RolePublisher, Domain: host,
		Exchanges: []*rampv1.AuthorizedExchange{{Domain: pushTestExchangeDomain, Ext: ext}},
	}, nil
}

// nopRegistry satisfies agentreg.Registry; PushResources never calls it (Gate 1,
// caller-signature, runs in the transport layer, not the service).
type nopRegistry struct{}

func (nopRegistry) LookupPublicKey(context.Context, string) (ed25519.PublicKey, error) {
	return nil, errors.New("not used")
}
func (nopRegistry) RegisterFromDirectory(context.Context, string, string) error { return nil }
func (nopRegistry) RefreshDirectoryKey(context.Context, string) error           { return nil }

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
	pool := servicetest.AcquireTestDB(t, ctx)

	// pt9 documented corner: no public tenant-provisioning RPC exists yet, and
	// TenantReadRepo exposes only ByID/ByDomain (no insert) — so this test arranges
	// its tenant prerequisite through the sqlc InsertTenant query, the same
	// surface every sibling Exchange test uses, rather than a raw SQL string.
	if _, err := sqlc.New(pool).InsertTenant(ctx, sqlc.InsertTenantParams{
		TenantID:        "t1",
		Domain:          "pub.example",
		Ed25519KeyRef:   "k",
		ReportingPolicy: []byte(`{}`),
		SigningScheme:   sqlc.RampSigningSchemeED25519,
	}); err != nil {
		t.Fatalf("seed tenant: %v", err)
	}

	realRepo := repo.NewCatalogRepo(sqlc.New(pool))
	failing := &failOnNthUpsertTx{CatalogRepo: realRepo, failAt: 2}
	svc := service.NewCatalogService(failing, repo.NewTenantReadRepo(sqlc.New(pool)), nopRegistry{}, authorizeAllManifests{},
		sharedb.PoolRunner{Pool: pool}, pushTestExchangeDomain)

	_, err := svc.PushResources(ctx, &rampv1.PushResourcesRequest{
		Exchange: pushTestExchangeDomain,
		Ver:      helpers.ProtocolVersion,
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
