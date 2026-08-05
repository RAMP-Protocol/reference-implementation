package keypolicy

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

// TestParseWindow pins fail-closed window parsing: empty bounds are unbounded
// (zero time, ok); a present-but-unparseable bound reports ok=false so the
// loader skips the malformed entry rather than treating a typo as unbounded
// (which would make an out-of-window key silently always-valid).
func TestParseWindow(t *testing.T) {
	if nb, na, ok := parseWindow("", ""); !ok || !nb.IsZero() || !na.IsZero() {
		t.Fatalf("empty window: want zero,zero,true; got %v,%v,%v", nb, na, ok)
	}
	if _, _, ok := parseWindow("2020-01-01T00:00:00Z", "2020-06-01T00:00:00Z"); !ok {
		t.Fatal("valid RFC 3339 window: want ok=true")
	}
	if _, _, ok := parseWindow("not-a-time", ""); ok {
		t.Fatal("unparseable not_before: want ok=false (fail-closed)")
	}
	if _, _, ok := parseWindow("", "also-bad"); ok {
		t.Fatal("unparseable not_after: want ok=false (fail-closed)")
	}
}

// TestDecodeTimedJWK_SkipsTypoedWindow drives the fail-closed skip one level
// above parseWindow, through the entry decode every JWKS loader shares: a
// structurally valid Ed25519 key whose window carries a typo must be skipped
// entirely. Deleting the parseWindow guard inside DecodeTimedJWK flips this
// test — the typo would decode as an unbounded, permanently valid key.
func TestDecodeTimedJWK_SkipsTypoedWindow(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	x := base64.RawURLEncoding.EncodeToString(pub)

	entry := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"not_after":"not-a-timestamp"}`, x)
	if _, ok := DecodeTimedJWK(json.RawMessage(entry)); ok {
		t.Fatal("entry with unparseable not_after decoded; a typo must never widen a key's validity")
	}

	valid := fmt.Sprintf(`{"kty":"OKP","crv":"Ed25519","x":%q,"not_before":"2026-08-01T00:00:00Z","not_after":"2026-10-30T00:00:00Z"}`, x)
	tk, ok := DecodeTimedJWK(json.RawMessage(valid))
	if !ok {
		t.Fatal("valid entry rejected")
	}
	if tk.NotBefore.IsZero() || tk.NotAfter.IsZero() {
		t.Fatalf("window bounds not carried: %v %v", tk.NotBefore, tk.NotAfter)
	}
}

// TestTimedKeyInWindow pins the use-time gate's edge semantics: half-open
// [NotBefore, NotAfter), and a zero bound open on that side.
func TestTimedKeyInWindow(t *testing.T) {
	nb := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	na := time.Date(2026, 10, 30, 0, 0, 0, 0, time.UTC)
	k := TimedKey{NotBefore: nb, NotAfter: na}

	tests := []struct {
		name string
		key  TimedKey
		now  time.Time
		want bool
	}{
		{"inside window", k, nb.Add(time.Hour), true},
		{"before not_before", k, nb.Add(-time.Second), false},
		{"exactly not_before is valid", k, nb, true},
		{"exactly not_after is expired", k, na, false},
		{"after not_after", k, na.Add(time.Second), false},
		{"no window is always valid", TimedKey{}, na.Add(time.Hour), true},
		{"open start", TimedKey{NotAfter: na}, nb.Add(-time.Hour), true},
		{"open end", TimedKey{NotBefore: nb}, na.Add(time.Hour), true},
	}
	for _, tc := range tests {
		if got := tc.key.InWindow(tc.now); got != tc.want {
			t.Errorf("%s: InWindow = %v, want %v", tc.name, got, tc.want)
		}
	}
}
