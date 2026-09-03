//go:build integration

package db_test

import (
	"context"
	"testing"

	sharedb "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/db"
)

// developerAccount is the one table 000006 touches.
const developerAccount = "developer_account"

// droppedColumns are the columns 000006 drops and its down restores: the four
// business-data columns the form fed, plus updated_at, which lost its only writer
// when the form's UPDATE went and can never move again.
var droppedColumns = []string{
	"legal_entity",
	"address",
	"jurisdiction_country",
	"registration_complete",
	"updated_at",
}

// TestDropDeveloperBusinessDataMigration verifies that 000006's down is the exact
// inverse of its up, and pins the four operational claims the down file makes to
// an operator who is mid-rollback.
//
// At head the dropped columns are gone and the table itself survives. Migrate(5)
// reverses 000006 and nothing below it, which must bring all of them back — at
// the declared defaults, at the declared types, NOT NULL as they were declared,
// with registration_complete back at false, and appended after created_at rather
// than in their original positions.
//
// Without this, a down that forgets one of the columns, or restores one at a
// different default, a different type or as nullable, passes every test in the
// repository: nothing else in the suite ever steps this schema backwards.
func TestDropDeveloperBusinessDataMigration(t *testing.T) {
	ctx := context.Background()
	dsn := sharedb.AcquireTestDSN(t, ctx, sharedPG)

	// At head: the four are dropped and the table stays. The up migration keeps
	// the table deliberately — identity.exchange_registration keys its rows to
	// this row's subdomain with ON DELETE CASCADE.
	if !schemaProbe.HasTable(t, ctx, dsn, developerAccount) {
		t.Fatal("after up: identity.developer_account was dropped, but 000006 only drops columns")
	}
	// created_at survives the drop; only updated_at goes. A change that took both
	// would leave the table with no record of when an account was provisioned.
	if !schemaProbe.HasColumn(t, ctx, dsn, developerAccount, "created_at") {
		t.Fatal("after up: identity.developer_account lost created_at, which 000006 does not drop")
	}
	for _, col := range droppedColumns {
		if schemaProbe.HasColumn(t, ctx, dsn, developerAccount, col) {
			t.Errorf("after up: identity.developer_account still has %s", col)
		}
	}
	// The columns the table is FOR must survive the drop.
	for _, col := range []string{"oidc_issuer", "oidc_subject", "email", "subdomain"} {
		if !schemaProbe.HasColumn(t, ctx, dsn, developerAccount, col) {
			t.Errorf("after up: identity.developer_account lost %s, which 000006 does not drop", col)
		}
	}

	m := schemaProbe.Migrator(t, dsn)
	defer m.Close()

	// Migrate to an explicit version rather than counting Steps(-1) from a moving
	// head: any migration added above 000006 would otherwise shift the step math.
	// Version 5 is the state immediately before 000006 ran.
	if err := m.Migrate(5); err != nil {
		t.Fatalf("migrate to version 5 (reverse 000006): %v", err)
	}

	for _, col := range droppedColumns {
		if !schemaProbe.HasColumn(t, ctx, dsn, developerAccount, col) {
			t.Errorf("after down: %s was not restored", col)
		}
	}

	// CONTENTS. The down file tells an operator every restored row comes back at
	// the column defaults, and singles out registration_complete coming back
	// false — a rolled-back binary then reads every existing developer as one who
	// has not completed sign-up. ADD COLUMN ... DEFAULT backfills every existing
	// row with that default, so the declared default is what each row holds.
	for _, tc := range []struct{ col, want string }{
		{"legal_entity", "''::text"},
		{"address", "''::text"},
		{"jurisdiction_country", "''::text"},
		{"registration_complete", "false"},
		{"updated_at", "now()"},
	} {
		if !schemaProbe.HasColumnDefault(t, ctx, dsn, developerAccount, tc.col, tc.want) {
			t.Errorf("after down: %s did not come back defaulting to %s", tc.col, tc.want)
		}
	}

	// TYPES. Four of the five are pinned by their defaults as a side effect — the
	// text casts carry the type, and false is boolean-specific. updated_at is not:
	// a down file that restored it as timestamp rather than timestamptz renders the
	// same now() default and passes every assertion above, while every timestamp the
	// service wrote would come back with its zone dropped. Asking the type directly
	// covers all five for the same price.
	for _, tc := range []struct{ col, want string }{
		{"legal_entity", "text"},
		{"address", "text"},
		{"jurisdiction_country", "text"},
		{"registration_complete", "boolean"},
		{"updated_at", "timestamp with time zone"},
	} {
		if !schemaProbe.HasColumnType(t, ctx, dsn, developerAccount, tc.col, tc.want) {
			t.Errorf("after down: %s did not come back as %s", tc.col, tc.want)
		}
	}

	// NULLABILITY. The down file restores all five NOT NULL, which is how they were
	// declared before 000006 dropped them. Postgres accepts NOT NULL here only
	// because each ADD COLUMN carries a DEFAULT that backfills the existing rows;
	// drop the DEFAULT from one and the migration fails on a populated table. The
	// defaults asserted above hold for a column restored as nullable too, so
	// without this a down that restored legal_entity as plain `text DEFAULT ''`
	// would pass every other assertion here.
	for _, col := range droppedColumns {
		if !schemaProbe.HasColumnNotNull(t, ctx, dsn, developerAccount, col) {
			t.Errorf("after down: %s came back nullable; 000006's down restores it NOT NULL", col)
		}
	}

	// POSITIONS. ADD COLUMN appends and Postgres cannot reorder, so the restored
	// columns land after created_at rather than in their original positions. The
	// down file says so, and says it is cosmetic; this pins the observation so the
	// claim and the schema cannot drift apart.
	for _, col := range droppedColumns {
		if !schemaProbe.ColumnComesAfter(t, ctx, dsn, developerAccount, col, "created_at") {
			t.Errorf("after down: %s did not come back appended after created_at", col)
		}
	}
}
