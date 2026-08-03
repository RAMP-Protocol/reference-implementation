//go:build integration

package tigerbeetle_test

import (
	"os"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// sharedTB is the package's single TigerBeetle container, brought up once by
// TestMain. Written once before m.Run and read-only thereafter; per-test
// isolation is the id salt (sharedTB.Salt), not a container reset.
var sharedTB *testutil.SharedTigerBeetle

// TestMain brings up one TigerBeetle container for the whole package via the
// shared container-only helper. os.Exit is delegated so the terminate defer runs.
func TestMain(m *testing.M) {
	os.Exit(testutil.RunTigerBeetleMain(m, func(tb *testutil.SharedTigerBeetle) { sharedTB = tb }))
}
