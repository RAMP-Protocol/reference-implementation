//go:build integration

package db_test

import (
	"context"
	"io"
	"log/slog"
	"testing"

	"github.com/google/uuid"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	brokerdb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db/sqlc"
)

func TestBrokerMigrationsSmoke(t *testing.T) {
	ctx := context.Background()
	dsn := sharedb.StartPostgres(t, ctx)
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	pool, err := sharedb.Setup(ctx, sharedb.SetupOptions{
		DSN:             dsn,
		Migrations:      brokerdb.Migrations,
		MigrationsDir:   brokerdb.MigrationsDir,
		MigrationsTable: brokerdb.MigrationsTable,
	}, logger)
	if err != nil {
		t.Fatalf("db setup: %v", err)
	}
	t.Cleanup(pool.Close)

	q := sqlc.New(pool)
	marketplaceID := "mp_" + uuid.NewString()

	mp, err := q.UpsertMarketplace(ctx, sqlc.UpsertMarketplaceParams{
		MarketplaceID:     marketplaceID,
		Domain:            marketplaceID + ".example",
		Endpoint:          "https://" + marketplaceID + ".example",
		TrustLevel:        sqlc.BrokerTrustLevelVERIFIED,
		SupportedProfiles: []byte(`["ramp-news-v1"]`),
		Priority:          10,
	})
	if err != nil {
		t.Fatalf("UpsertMarketplace: %v", err)
	}

	rows, err := q.ListActiveMarketplaces(ctx)
	if err != nil {
		t.Fatalf("ListActiveMarketplaces: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.MarketplaceID == mp.MarketplaceID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected marketplace %q in ListActiveMarketplaces", marketplaceID)
	}
}
