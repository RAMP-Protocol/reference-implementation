package tigerbeetle

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"

	tb "github.com/tigerbeetle/tigerbeetle-go"
)

// ID is a TigerBeetle 128-bit account or transfer identifier, aliased so callers
// outside this package (e.g. the billing adapter) need not import the TigerBeetle
// client directly.
type ID = tb.Uint128

// Prefix namespaces a business id before it is hashed into a TigerBeetle account
// id, so ids in different roles never collide for equal business ids. The payee
// prefix is "owner:" (the resource owner), not "publisher:".
type Prefix string

// Account-id namespacing prefixes; the payee prefix is "owner:", not "publisher:".
const (
	PrefixAgent    Prefix = "agent:"
	PrefixOwner    Prefix = "owner:"
	PrefixPlatform Prefix = "platform:"
)

// Account business-id fragments, paired with PrefixOwner and PrefixPlatform. The
// resource-owner revenue account is AccountID(PrefixOwner, OwnerRevenuePrefix+
// resource_owner_id); the single platform commission account is
// AccountID(PrefixPlatform, PlatformFeeID). Kept here (shared) so the production
// adapter and the integration-test fixtures name the same accounts from one
// source rather than re-hardcoding the literals.
const (
	OwnerRevenuePrefix = "revenue:"
	PlatformFeeID      = "fee"
	// PlatformLiquidityID names the operator liquidity account welcome credits
	// are drawn from: AccountID(PrefixPlatform, PlatformLiquidityID). The same
	// account the operator funding scripts debit — it carries no
	// DebitsMustNotExceedCredits flag, so it may go arbitrarily negative (it
	// represents money owed by the platform, not a prepaid balance).
	PlatformLiquidityID = "liquidity"
)

// Transfer id-derivation namespaces for the transaction lifecycle's own
// transfers. Each is prepended to a business id before it is hashed into a
// TigerBeetle transfer id (TransferID below).
//
// They are constants because two places must agree on them: the adapter that
// derives lifecycle transfer ids, and billing's shared Credit gate, which
// refuses a caller-supplied credit key starting with any of them — such a key
// could derive the same transfer id as a lifecycle transfer and misfile the
// grant. Written as literals at each site, adding a sixth namespace would leave
// the gate unaware of it, and renaming one would leave the gate guarding a
// prefix nothing derives.
const (
	TransferPendingPrefix = "pending:"
	TransferPostPrefix    = "post:"
	TransferVoidPrefix    = "void:"
	TransferFeePrefix     = "fee:"
	TransferRefundPrefix  = "refund:"
)

// AccountCode classifies an account's category. It is a distinct named type from
// TransferCode (split.go) so an account code and a transfer code cannot be passed
// where the other is expected — both would otherwise be bare uint16. TigerBeetle
// requires a non-zero code and exposes it as a query_accounts filter dimension.
// Because the account id is a hash (its prefix is unrecoverable from the ledger),
// the code is the only ledger-native way to query accounts by category.
type AccountCode uint16

// The account-category codes. TigerBeetle rejects code 0, so these start at 1.
const (
	CodeAgent    AccountCode = 1
	CodeOwner    AccountCode = 2
	CodePlatform AccountCode = 3
)

// maxUint128Bytes is the all-ones reserved id (2^128-1); TigerBeetle forbids it
// along with zero.
var maxUint128Bytes = [16]byte{
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
}

// AccountID maps (prefix, businessID) to a deterministic TigerBeetle account id:
// the low 16 bytes of sha256(prefix || businessID). Phase 1 is single-currency,
// so the ledger/currency is deliberately not folded in; multi-currency must key
// the id by currency too, because a TigerBeetle id is unique per cluster, not per
// ledger. Returns ErrEmptyID for an empty business id.
func AccountID(p Prefix, businessID string) (tb.Uint128, error) {
	if businessID == "" {
		return tb.Uint128{}, ErrEmptyID
	}
	return reduce(sha256.Sum256([]byte(string(p) + businessID)))
}

// TransferID maps an idempotency key to a deterministic TigerBeetle transfer id
// (the low 16 bytes of sha256(key)). A retry re-derives the same id, so
// TigerBeetle's duplicate-id rejection is the idempotency guard (used by the
// lifecycle and settlement paths). Returns ErrEmptyID for an empty key.
func TransferID(idempotencyKey string) (tb.Uint128, error) {
	if idempotencyKey == "" {
		return tb.Uint128{}, ErrEmptyID
	}
	return reduce(sha256.Sum256([]byte(idempotencyKey)))
}

// reduce folds a 32-byte digest into a 16-byte TigerBeetle id (the low 16 bytes)
// and rejects the two reserved values. The reserved check is on the raw bytes, so
// it is correct regardless of Uint128 byte order (all-zero bytes = 0, all-0xFF
// bytes = 2^128-1). The byte->Uint128 interpretation is fixed by BytesToUint128,
// so every caller derives byte-identical ids.
func reduce(sum [32]byte) (tb.Uint128, error) {
	var b [16]byte
	copy(b[:], sum[:16])
	if b == ([16]byte{}) || b == maxUint128Bytes {
		return tb.Uint128{}, ErrReservedID
	}
	return tb.BytesToUint128(b), nil
}

// DefaultFlagsForCode is the account-flag policy per category, in one place so a
// caller never has to remember a second override. Agent accounts are prepaid, so
// they get DebitsMustNotExceedCredits (a hold or settlement is rejected once the
// funded balance is exhausted) and no history (agent balance history is not needed
// in v1). Owner and platform accounts enable History so the reporting reads
// (GetAccountBalances) have the historical series. Folding the agent policy in
// here removes the DefaultFlagsForCode+AgentAccountFlags override pair whose
// omission silently dropped the agent debit cap.
func DefaultFlagsForCode(code AccountCode) tb.AccountFlags {
	if code == CodeAgent {
		return AgentAccountFlags()
	}
	return tb.AccountFlags{History: true}
}

// IDFromUint64 packs a small unsigned value into the low bits of an ID. It carries
// application scalars (e.g. the fee rate in basis points) in a transfer's user_data
// without the caller importing the TigerBeetle client. Recover the value with
// ID.BigInt().
func IDFromUint64(v uint64) ID {
	return tb.ToUint128(v)
}

// ReasonToken packs the first 8 bytes of sha256(reason) into a uint64 — a
// verifiable, PII-free token suitable for a transfer's user_data_64 (e.g. a refund
// dispute reason, so a persisted refund carries audit evidence of its reason). An
// empty reason yields 0. Nothing is recoverable from the token directly; it is an
// equality witness, matched by recomputing the hash of a claimed reason.
func ReasonToken(reason string) uint64 {
	if reason == "" {
		return 0
	}
	sum := sha256.Sum256([]byte(reason))
	return binary.BigEndian.Uint64(sum[:8])
}

// EncodeID renders an ID as a fixed 32-character hex string (its little-endian
// bytes). Used as the adapter's opaque BillingID and as a stable map key for
// id-set membership.
func EncodeID(id ID) string {
	b := id.Bytes()
	return hex.EncodeToString(b[:])
}

// DecodeID parses a string produced by EncodeID back into an ID. A string that is
// not exactly 16 bytes of hex returns ErrBadID.
func DecodeID(s string) (ID, error) {
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 16 {
		return ID{}, fmt.Errorf("%w: %q", ErrBadID, s)
	}
	var arr [16]byte
	copy(arr[:], b)
	return tb.BytesToUint128(arr), nil
}
