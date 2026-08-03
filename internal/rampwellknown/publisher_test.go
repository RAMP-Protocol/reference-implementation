package rampwellknown_test

import (
	"testing"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"google.golang.org/protobuf/types/known/structpb"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// exchangeWithOwner builds an AuthorizedExchange for domain whose ext attests
// ownerID. An empty ownerID still sets the ext key (to an empty string), so the
// "present but empty" case is distinct from the "no ext at all" case below.
func exchangeWithOwner(t *testing.T, domain, ownerID string) *rampv1.AuthorizedExchange {
	t.Helper()
	ext, err := structpb.NewStruct(map[string]any{"resource_owner_id": ownerID})
	if err != nil {
		t.Fatalf("structpb.NewStruct: %v", err)
	}
	return &rampv1.AuthorizedExchange{Domain: domain, Ext: ext}
}

func TestResourceOwnerID(t *testing.T) {
	t.Parallel()
	const exch = "exchange.example"
	tests := []struct {
		name      string
		exchanges []*rampv1.AuthorizedExchange
		domain    string
		wantID    string
		wantOK    bool
	}{
		{
			name:      "match returns attested owner",
			exchanges: []*rampv1.AuthorizedExchange{exchangeWithOwner(t, exch, "owner-acme")},
			domain:    exch,
			wantID:    "owner-acme",
			wantOK:    true,
		},
		{
			name:      "no exchange entry",
			exchanges: nil,
			domain:    exch,
			wantOK:    false,
		},
		{
			name:      "matching entry without ext",
			exchanges: []*rampv1.AuthorizedExchange{{Domain: exch}},
			domain:    exch,
			wantOK:    false,
		},
		{
			name:      "matching entry with empty owner value",
			exchanges: []*rampv1.AuthorizedExchange{exchangeWithOwner(t, exch, "")},
			domain:    exch,
			wantOK:    false,
		},
		{
			name:      "non-matching exchange domain ignored",
			exchanges: []*rampv1.AuthorizedExchange{exchangeWithOwner(t, "other.exchange", "owner-acme")},
			domain:    exch,
			wantOK:    false,
		},
		{
			name: "first matching entry wins among several",
			exchanges: []*rampv1.AuthorizedExchange{
				exchangeWithOwner(t, "other.exchange", "owner-x"),
				exchangeWithOwner(t, exch, "owner-acme"),
			},
			domain: exch,
			wantID: "owner-acme",
			wantOK: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			m := &rampwellknown.Manifest{
				Ver:       rampwellknown.Version,
				Role:      rampwellknown.RolePublisher,
				Domain:    "pub.example",
				Exchanges: tc.exchanges,
			}
			gotID, gotOK := rampwellknown.ResourceOwnerID(m, tc.domain)
			if gotID != tc.wantID || gotOK != tc.wantOK {
				t.Fatalf("ResourceOwnerID = (%q, %v), want (%q, %v)", gotID, gotOK, tc.wantID, tc.wantOK)
			}
		})
	}

	t.Run("nil manifest", func(t *testing.T) {
		t.Parallel()
		if id, ok := rampwellknown.ResourceOwnerID(nil, exch); ok || id != "" {
			t.Fatalf("nil manifest = (%q, %v), want empty/false", id, ok)
		}
	})
	t.Run("empty exchange domain", func(t *testing.T) {
		t.Parallel()
		m := &rampwellknown.Manifest{Exchanges: []*rampv1.AuthorizedExchange{exchangeWithOwner(t, exch, "owner-acme")}}
		if id, ok := rampwellknown.ResourceOwnerID(m, ""); ok || id != "" {
			t.Fatalf("empty domain = (%q, %v), want empty/false", id, ok)
		}
	})
}
