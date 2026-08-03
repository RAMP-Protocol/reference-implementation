//go:build integration

package db_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// checkViolationSQLState is SQLSTATE 23514 (check_violation).
const checkViolationSQLState = "23514"

// validEd25519SigHex is a well-formed 64-byte Ed25519 signature rendered as the
// 128 lowercase hex characters both signature columns accept.
const validEd25519SigHex = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef" +
	"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

// assertColumnShape covers every value-shape constraint 000024 puts on
// transaction_evidence: both signature columns must hold a 64-byte Ed25519
// signature in hex, both verifying public keys must be exactly 32 bytes,
// requester_domain must fit the RFC 1035 octet bound, and request_id must travel
// with its provenance flag.
//
// The rows go into a TEMP table declared LIKE the real one. INCLUDING
// CONSTRAINTS copies the CHECK constraints — the properties under test — and
// NOT NULL comes along unconditionally; INCLUDING DEFAULTS is needed for
// created_at, whose NOT NULL is copied but whose DEFAULT NOW() would not be.
// Postgres never copies foreign keys or triggers through LIKE, which is what
// makes this work: no transaction_log or tenants parent row is needed, and a
// rejected INSERT is unambiguously a CHECK firing rather than the append-once
// guard. One pooled connection is held throughout because a TEMP table is
// session-scoped.
func assertColumnShape(t *testing.T, ctx context.Context, dsn string) {
	t.Helper()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	defer pool.Close()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	defer conn.Release()
	if _, err := conn.Exec(ctx,
		`CREATE TEMP TABLE evidence_shape (
			LIKE ramp.transaction_evidence INCLUDING CONSTRAINTS INCLUDING DEFAULTS
		)`); err != nil {
		t.Fatalf("create shape table: %v", err)
	}

	t.Run("signature columns", func(t *testing.T) { assertSignatureShape(t, ctx, conn) })
	t.Run("public key columns", func(t *testing.T) { assertPublicKeyShape(t, ctx, conn) })
	t.Run("requester domain bound", func(t *testing.T) { assertRequesterDomainShape(t, ctx, conn) })
	t.Run("request id provenance", func(t *testing.T) { assertRequestIDProvenanceShape(t, ctx, conn) })
}

// assertSignatureShape pins what the two hex signature columns accept. The
// uppercase case is load-bearing rather than incidental: agent_acceptance_signature
// arrives off the wire and hex decoding is case-insensitive, so a signature that
// has ALREADY verified may be uppercase. A constraint that rejected it would turn
// a valid execute into a write failure.
func assertSignatureShape(t *testing.T, ctx context.Context, conn *pgxpool.Conn) {
	t.Helper()
	const shortHex = "0123456789abcdef"
	nonHex := repeatTo("zz", len(validEd25519SigHex))
	cases := []struct {
		name          string
		offerSig      string
		acceptanceSig string
		wantRejected  bool
	}{
		{"both well-formed", validEd25519SigHex, validEd25519SigHex, false},
		{"uppercase hex is accepted", upper(validEd25519SigHex), upper(validEd25519SigHex), false},
		{"empty offer signature", "", validEd25519SigHex, true},
		{"empty acceptance signature", validEd25519SigHex, "", true},
		{"non-hex offer signature", nonHex, validEd25519SigHex, true},
		{"non-hex acceptance signature", validEd25519SigHex, nonHex, true},
		{"truncated offer signature", shortHex, validEd25519SigHex, true},
		{"truncated acceptance signature", validEd25519SigHex, shortHex, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validShapeRow()
			r.offerSig, r.acceptanceSig = tc.offerSig, tc.acceptanceSig
			assertCheckOutcome(t, insertShapeRow(ctx, conn, r), tc.wantRejected)
		})
	}
}

// assertPublicKeyShape pins both verifying keys at exactly 32 bytes. The columns
// are BYTEA and the CHECKs are the only thing standing between a truncated or
// padded key and a row that can never be re-verified — ed25519.Verify on a
// wrong-length key does not error, it simply reports false, so a malformed key
// stored here would read as "the signature does not verify" forever after.
func assertPublicKeyShape(t *testing.T, ctx context.Context, conn *pgxpool.Conn) {
	t.Helper()
	key := func(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }
	cases := []struct {
		name         string
		exchangeKey  []byte
		agentKey     []byte
		wantRejected bool
	}{
		{"both exactly 32 bytes", key(0xa1, 32), key(0xb2, 32), false},
		{"exchange key one byte short", key(0xa1, 31), key(0xb2, 32), true},
		{"exchange key one byte long", key(0xa1, 33), key(0xb2, 32), true},
		// Empty (not NULL) — a zero-length BYTEA must be refused by the CHECK, not
		// by NOT NULL, or the case would pass for the wrong reason.
		{"exchange key empty", []byte{}, key(0xb2, 32), true},
		{"agent key one byte short", key(0xa1, 32), key(0xb2, 31), true},
		{"agent key one byte long", key(0xa1, 32), key(0xb2, 33), true},
		{"agent key empty", key(0xa1, 32), []byte{}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validShapeRow()
			r.exchangeKey, r.agentKey = tc.exchangeKey, tc.agentKey
			assertCheckOutcome(t, insertShapeRow(ctx, conn, r), tc.wantRejected)
		})
	}
}

// assertRequesterDomainShape pins the RFC 1035 bound on requester_domain, the one
// caller-influenced value in the row that nothing upstream constrains.
//
// The unit is what this exists to pin. RFC 1035 counts OCTETS, the service guard
// counts bytes (Go's len), and the CHECK must agree — a character-counting CHECK
// admits an internationalized domain of 253 characters and roughly 600 bytes,
// making the layer designated as the structural backstop the looser of the two.
// The multi-byte case below is that exact shape: well inside any character bound,
// far outside the octet bound.
func assertRequesterDomainShape(t *testing.T, ctx context.Context, conn *pgxpool.Conn) {
	t.Helper()
	const maxDomainOctets = 253
	cases := []struct {
		name         string
		domain       string
		wantRejected bool
	}{
		{"at the bound", strings.Repeat("a", maxDomainOctets), false},
		{"one octet over", strings.Repeat("a", maxDomainOctets+1), true},
		{"empty", "", false},
		// 200 two-byte characters: 200 characters, 400 octets. Accepted by a
		// character-counting CHECK, refused by an octet-counting one.
		{"multi-byte, under the character bound but over the octet bound", strings.Repeat("é", 200), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validShapeRow()
			r.requesterDomain = tc.domain
			assertCheckOutcome(t, insertShapeRow(ctx, conn, r), tc.wantRejected)
		})
	}
}

// assertRequestIDProvenanceShape pins the coupling between request_id and
// request_id_minted. A stored id without its provenance is unreadable — a minted
// UUID and a conforming caller-supplied value are byte-identical in shape — and a
// provenance without an id describes nothing.
func assertRequestIDProvenanceShape(t *testing.T, ctx context.Context, conn *pgxpool.Conn) {
	t.Helper()
	cases := []struct {
		name         string
		requestID    *string
		minted       *bool
		wantRejected bool
	}{
		{"id with minted provenance", strPtr("req-1"), boolPtr(true), false},
		{"id with caller-supplied provenance", strPtr("req-1"), boolPtr(false), false},
		{"neither id nor provenance", nil, nil, false},
		{"id without provenance", strPtr("req-1"), nil, true},
		{"provenance without id", nil, boolPtr(true), true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := validShapeRow()
			r.requestID, r.requestIDMinted = tc.requestID, tc.minted
			assertCheckOutcome(t, insertShapeRow(ctx, conn, r), tc.wantRejected)
		})
	}
}

// shapeRow names every column a shape case can vary — one field per CHECK the
// migration declares.
type shapeRow struct {
	offerSig        string
	acceptanceSig   string
	requestID       *string
	requestIDMinted *bool
	requesterDomain string
	exchangeKey     []byte
	agentKey        []byte
}

// validShapeRow is a row every CHECK accepts. Cases start from it and vary only
// the column under test, so a rejection can come from nothing else — and the
// "accepted" cases prove the baseline is genuinely valid rather than passing
// because some other column happened to be malformed in a compensating way.
func validShapeRow() shapeRow {
	return shapeRow{
		offerSig:        validEd25519SigHex,
		acceptanceSig:   validEd25519SigHex,
		requestID:       strPtr("req-1"),
		requestIDMinted: boolPtr(true),
		requesterDomain: "agent.example",
		exchangeKey:     bytes.Repeat([]byte{0xa1}, 32),
		agentKey:        bytes.Repeat([]byte{0xb2}, 32),
	}
}

// insertShapeRow writes one row into the TEMP shape table and returns the raw
// error so the caller can classify it. Every row uses a fresh transaction_id, so
// cases stay independent without any cleanup.
func insertShapeRow(ctx context.Context, conn *pgxpool.Conn, r shapeRow) error {
	const q = `
		INSERT INTO evidence_shape (
			transaction_id, tenant_id,
			offer_id, offer_json, offer_canonical_bytes,
			offer_signature, offer_signature_algorithm, exchange_signing_public_key,
			agent_acceptance_signature, agent_acceptance_canonical_bytes,
			agent_acceptance_signature_algorithm,
			requester_id, requester_domain, request_idempotency_key,
			agent_public_key, agent_discovery_url,
			signed_url_full, request_id, request_id_minted
		) VALUES (
			gen_random_uuid()::text, 'tenant-shape',
			'offer-shape', '{}'::jsonb, '\x00'::bytea,
			$1, 'EdDSA', $5,
			$2, '\x00'::bytea,
			'EdDSA',
			'agent-shape', $7, 'idem-shape',
			$6, '',
			'https://cdn.example/x', $3, $4
		)`
	_, err := conn.Exec(ctx, q,
		r.offerSig, r.acceptanceSig, r.requestID, r.requestIDMinted,
		r.exchangeKey, r.agentKey, r.requesterDomain)
	return err
}

// assertCheckOutcome asserts an INSERT was either accepted or refused by a CHECK
// constraint specifically — not by some other constraint that would make the case
// pass for the wrong reason.
func assertCheckOutcome(t *testing.T, err error, wantRejected bool) {
	t.Helper()
	if !wantRejected {
		if err != nil {
			t.Fatalf("INSERT rejected but should have been accepted: %v", err)
		}
		return
	}
	if err == nil {
		t.Fatal("INSERT accepted but a CHECK constraint should have refused it")
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != checkViolationSQLState {
		t.Fatalf("INSERT refused with %v, want SQLSTATE %s (check_violation)", err, checkViolationSQLState)
	}
}

// repeatTo builds a string of exactly n characters by repeating unit.
func repeatTo(unit string, n int) string {
	out := ""
	for len(out) < n {
		out += unit
	}
	return out[:n]
}

// upper uppercases the ASCII hex letters, leaving digits alone.
func upper(s string) string {
	b := []byte(s)
	for i, c := range b {
		if c >= 'a' && c <= 'f' {
			b[i] = c - ('a' - 'A')
		}
	}
	return string(b)
}

func strPtr(s string) *string { return &s }

func boolPtr(b bool) *bool { return &b }
