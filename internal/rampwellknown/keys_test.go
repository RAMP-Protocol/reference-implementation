package rampwellknown_test

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown/testutil"
)

var anchor = time.Date(2026, 6, 3, 12, 0, 0, 0, time.UTC)

func keyWindow(kid string, fromOffset, untilOffset time.Duration) *rampwellknown.Key {
	_, k := testutil.NewSigningKey(kid, anchor.Add(fromOffset), anchor.Add(untilOffset))
	return k
}

func TestKeyFromEncodedX_RoundTrip(t *testing.T) {
	t.Parallel()
	// src.X is already base64url of the pubkey; KeyFromEncodedX must carry it
	// verbatim under the fixed RFC 8037 header quad and decode back identically.
	priv, src := testutil.NewSigningKey("k1", anchor.Add(-time.Hour), anchor.Add(time.Hour))
	k := rampwellknown.KeyFromEncodedX("k2", src.GetX(), "2026-01-01T00:00:00Z", "2027-01-01T00:00:00Z")
	if k.GetKty() != "OKP" || k.GetCrv() != "Ed25519" || k.GetUse() != "sig" || k.GetAlg() != "EdDSA" {
		t.Fatalf("unexpected JWK header quad: %+v", k)
	}
	pub, err := rampwellknown.PublicKey(k)
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	if !pub.Equal(priv.Public()) {
		t.Fatal("decoded key does not match the source pubkey")
	}
}

func TestActiveKeys_WindowEdges(t *testing.T) {
	t.Parallel()
	hour := time.Hour
	tests := []struct {
		name string
		key  *rampwellknown.Key
		want bool
	}{
		{"inside window", keyWindow("inside", -hour, hour), true},
		{"not_before == now is active (inclusive lower)", keyWindow("lower", 0, hour), true},
		{"not_after == now is inactive (exclusive upper)", keyWindow("upper", -hour, 0), false},
		{"entirely future", keyWindow("future", hour, 2*hour), false},
		{"entirely past", keyWindow("past", -2*hour, -hour), false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := testutil.Manifest(rampwellknown.RoleExchange, "x.example", tc.key)
			active := rampwellknown.ActiveKeys(m, anchor)
			got := len(active) == 1
			if got != tc.want {
				t.Fatalf("ActiveKeys active=%v, want %v (count=%d)", got, tc.want, len(active))
			}
		})
	}
}

func TestActiveKeys_PreservesOrderAndFilters(t *testing.T) {
	t.Parallel()
	m := testutil.Manifest(
		rampwellknown.RoleBroker, "b.example",
		keyWindow("k1", -time.Hour, time.Hour),
		keyWindow("expired", -2*time.Hour, -time.Hour),
		keyWindow("k2", -time.Minute, time.Hour),
	)
	active := rampwellknown.ActiveKeys(m, anchor)
	if len(active) != 2 {
		t.Fatalf("want 2 active, got %d", len(active))
	}
	if active[0].GetKid() != "k1" || active[1].GetKid() != "k2" {
		t.Fatalf("order not preserved: %s, %s", active[0].GetKid(), active[1].GetKid())
	}
}

func TestKeyByKid(t *testing.T) {
	t.Parallel()
	m := testutil.Manifest(rampwellknown.RoleAgent, "a.example",
		keyWindow("present", -time.Hour, time.Hour))
	if k, ok := rampwellknown.KeyByKid(m, "present"); !ok || k.GetKid() != "present" {
		t.Fatalf("expected to find kid present, ok=%v", ok)
	}
	if _, ok := rampwellknown.KeyByKid(m, "absent"); ok {
		t.Fatal("expected miss for absent kid")
	}
	if _, ok := rampwellknown.KeyByKid(nil, "present"); ok {
		t.Fatal("expected miss for nil manifest")
	}
}

func TestPublicKey_DecodeAndReject(t *testing.T) {
	t.Parallel()
	priv, k := testutil.NewSigningKey("k", anchor, anchor.Add(time.Hour))
	pub, err := rampwellknown.PublicKey(k)
	if err != nil {
		t.Fatalf("decode valid key: %v", err)
	}
	want, _ := priv.Public().(ed25519.PublicKey)
	if !pub.Equal(want) {
		t.Fatal("decoded key does not match generator")
	}

	short := &rampwellknown.Key{X: base64.RawURLEncoding.EncodeToString(make([]byte, 31))}
	if _, err := rampwellknown.PublicKey(short); !errors.Is(err, rampwellknown.ErrSchemaInvalid) {
		t.Fatalf("short key: want ErrSchemaInvalid, got %v", err)
	}
	bad := &rampwellknown.Key{X: "not!base64!"}
	if _, err := rampwellknown.PublicKey(bad); !errors.Is(err, rampwellknown.ErrSchemaInvalid) {
		t.Fatalf("bad base64: want ErrSchemaInvalid, got %v", err)
	}
}
