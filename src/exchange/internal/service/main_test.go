//go:build integration

package service_test

import (
	"os"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	exchangedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/db"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service/servicetest"
)

// TestMain brings up one shared migrated Postgres for the whole service test
// binary — which spans package service and package service_test — and hands it to
// the servicetest bridge so every integration test acquires a reset database
// through servicetest.AcquireTestDB (Testing Doctrine §11). os.Exit is delegated to
// RunIntegrationMain so the container-terminate defer runs.
func TestMain(m *testing.M) {
	os.Exit(testutil.RunIntegrationMain(m, exchangedb.Migrations,
		exchangedb.MigrationsDir, exchangedb.MigrationsTable, servicetest.Assign))
}
