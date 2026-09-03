//go:build integration

package db_test

import (
	"context"
	"testing"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
)

// indexName is the object 000030 creates. The reporting-compliance aggregate
// depends on it: that query filters on transaction_log (tenant_id, agent_id) and
// joins reporting_obligations on transaction_id, so it carries no predicate on
// the obligations table and no other index on that table can serve it. Without
// this one Postgres reads the whole table, once per executed item, in front of
// fund reservation.
//
// The query's comment states that dependency as fact. This test is what keeps
// the statement true: drop the index in a later migration, rename it, or build
// it on the wrong columns, and this fails rather than the purchase path quietly
// getting slower.
const indexName = "reporting_obligations_transaction_idx"

// hasReportingTransactionIndex reports whether the index exists AND is usable.
// indisvalid is checked, not just the name: a CREATE INDEX CONCURRENTLY that
// fails part way leaves an INVALID index of the right name behind, which the
// planner will not use. Matching on the name alone would call that success.
func hasReportingTransactionIndex(t *testing.T, ctx context.Context, dsn string) bool {
	t.Helper()
	return schemaProbe.Exists(t, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1
			  FROM pg_index AS i
			  JOIN pg_class AS c ON c.oid = i.indexrelid
			  JOIN pg_namespace AS n ON n.oid = c.relnamespace
			 WHERE n.nspname = 'ramp' AND c.relname = $1 AND i.indisvalid
		)`, indexName)
}

// TestReportingObligationTransactionIndexMigration verifies 000030 both ways:
// at head the index exists on the columns the compliance aggregate needs, and
// stepping down to version 29 removes it, proving the down file is the exact
// inverse of the up. Migrate(29) is an explicit version rather than Steps(-1)
// so later migrations stacking on top do not shift the math.
func TestReportingObligationTransactionIndexMigration(t *testing.T) {
	ctx := context.Background()
	dsn := sharedb.AcquireTestDSN(t, ctx, sharedPG)

	if !hasReportingTransactionIndex(t, ctx, dsn) {
		t.Fatalf("after up: %s is missing or invalid", indexName)
	}

	// The definition, not just the name. An index of this name on different
	// columns would not serve the join, and the query comment's claim would be
	// false while a name-only check still passed. The key column is what makes
	// the join an index probe; the INCLUDE columns are the two the aggregate
	// groups on, which is what lets the probe stay off the heap.
	if !schemaProbe.Exists(t, ctx, dsn, `
		SELECT EXISTS (
			SELECT 1 FROM pg_indexes
			 WHERE schemaname = 'ramp'
			   AND tablename  = 'reporting_obligations'
			   AND indexname  = $1
			   AND indexdef LIKE '%(transaction_id)%'
			   AND indexdef LIKE '%INCLUDE (state, deadline)%'
		)`, indexName) {
		t.Errorf("after up: %s is not on (transaction_id) INCLUDE (state, deadline)", indexName)
	}

	m := schemaProbe.Migrator(t, dsn)

	if err := m.Migrate(29); err != nil {
		t.Fatalf("migrate to version 29 (reverse 000030): %v", err)
	}
	if hasReportingTransactionIndex(t, ctx, dsn) {
		t.Errorf("after down 000030: %s still exists", indexName)
	}
}
