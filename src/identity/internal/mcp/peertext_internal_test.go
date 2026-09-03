package mcp

import (
	"errors"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/exchacct"
)

// boundPeerText is driven here rather than through the MCP surface because the
// property is an exact byte offset. Over the wire the bounded string carries a
// rendered prefix this test does not control, so it cannot place a character
// across the cut on purpose — the integration test beside it pins that the bound
// fires and what it removes, and this one pins where it cuts. Same reasoning as
// caller_internal_test.go.

// TestBoundPeerText_CutsOnACharacterBoundary is the byte-offset half of the same
// bound, as pure logic.
//
// A third party writes this text and may write it in any language, so a cut at a
// fixed byte offset lands inside a multi-byte character often rather than rarely.
// The behavioural test above cannot pin this: it does not control the rendered
// prefix, so it cannot place a character across byte 300 on purpose. The offsets
// here do, one for each length of multi-byte character.
func TestBoundPeerText_CutsOnACharacterBoundary(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name string
		r    rune
	}{
		{"two-byte", 'é'},
		{"three-byte", '—'},
		{"four-byte", '😀'},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			size := utf8.RuneLen(tc.r)
			// Straddle the cut: pad so byte maxPeerText falls strictly inside the
			// next character, then repeat it well past the bound.
			for pad := maxPeerText - size + 1; pad < maxPeerText; pad++ {
				in := strings.Repeat("a", pad) + strings.Repeat(string(tc.r), maxPeerText)
				got := boundPeerText(in)
				if !utf8.ValidString(got) {
					t.Fatalf("pad=%d: the cut left invalid UTF-8, which renders as U+FFFD "+
						"in front of the marker: %q", pad, got)
				}
				if !strings.HasSuffix(got, "… (truncated)") {
					t.Fatalf("pad=%d: the cut is not marked: %q", pad, got)
				}
			}
		})
	}
}

// TestBoundPeerCause_SpendsTheBudgetOnThePeersText pins which half of the
// rendered error the bound applies to.
//
// This service builds the "exchacct: outbound at <domain>: " prefix, and a bare
// domain may be helpers.MaxBareDomainLen bytes. Bounding the rendered whole
// therefore spends the peer's budget on our own text, and at the longest legal
// domain it leaves the operator none of the peer's sentence at all — which is
// the one thing on the line they can act on.
//
// The integration test beside this one cannot show the difference: its Exchange
// double is served on a loopback address about fifteen bytes long, so both
// spellings of the bound produce the same line there.
func TestBoundPeerCause_SpendsTheBudgetOnThePeersText(t *testing.T) {
	t.Parallel()
	const head = "refused, you sent: "
	domain := strings.Repeat("a", helpers.MaxBareDomainLen-len(".example")) + ".example"
	if !helpers.IsBareDomain(domain) {
		t.Fatalf("the test domain is not one an agent could name: %d bytes", len(domain))
	}
	err := &exchacct.Error{
		Kind:     exchacct.KindOutbound,
		Exchange: domain,
		Err:      errors.New(head + strings.Repeat("x", 4096)),
	}

	got := boundPeerCause(err)
	if !strings.Contains(got, head) {
		t.Errorf("the peer's sentence is gone from the operator line, so the budget "+
			"was spent on this service's own %d-byte prefix: %q", len(domain), got)
	}
	if !strings.Contains(got, domain) {
		t.Errorf("the operator line no longer names the Exchange: %q", got)
	}
	if !strings.HasSuffix(got, "… (truncated)") {
		t.Errorf("the peer's text was not bounded: %q", got)
	}
}

// TestBoundPeerCause_BoundsTheWholeWhenThereIsNoCause is the fallback arm: an
// error this package cannot take apart is bounded entire, which is never less
// bounded than before.
func TestBoundPeerCause_BoundsTheWholeWhenThereIsNoCause(t *testing.T) {
	t.Parallel()
	got := boundPeerCause(errors.New(strings.Repeat("x", 4096)))
	if !strings.HasSuffix(got, "… (truncated)") {
		t.Errorf("a foreign error reached the operator line unbounded: %d bytes", len(got))
	}
}
