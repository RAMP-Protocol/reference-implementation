//go:build integration

package db_test

import (
	"context"
	"testing"

	"github.com/google/uuid"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	brokerdb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/db/sqlc"
)

func TestBrokerMigrationsSmoke(t *testing.T) {
	ctx := context.Background()
	dsn := sharedb.StartPostgres(t, ctx)
	logger := testutil.DiscardLogger()

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
	exchangeID := "ex_" + uuid.NewString()

	ex, err := q.UpsertExchange(ctx, sqlc.UpsertExchangeParams{
		ExchangeID:        exchangeID,
		Domain:            exchangeID + ".example",
		Endpoint:          "https://" + exchangeID + ".example",
		TrustLevel:        sqlc.BrokerTrustLevelVERIFIED,
		SupportedProfiles: []byte(`["ramp-news-v1"]`),
		Priority:          10,
	})
	if err != nil {
		t.Fatalf("UpsertExchange: %v", err)
	}

	rows, err := q.ListUnblockedExchanges(ctx)
	if err != nil {
		t.Fatalf("ListUnblockedExchanges: %v", err)
	}
	found := false
	for _, r := range rows {
		if r.ExchangeID == ex.ExchangeID {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected exchange %q in ListUnblockedExchanges", exchangeID)
	}
}
