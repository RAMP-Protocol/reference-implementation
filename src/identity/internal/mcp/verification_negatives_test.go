//go:build integration

package mcp_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
)

// TestDiscover_UnverifiableOfferIsRejectedNotReturned is the negative half of
// the property this adapter gained: discovery verifies.
//
// An agent reached through this surface runs no verifier of its own, so an offer
// the Broker relays is checked HERE or nowhere. The Broker forwards offers it did
// not mint, which is precisely the case: a doctored offer would otherwise steer
// the agent's choice and fail much later, at the purchase, pointing at the agent
// rather than at the relay that altered it.
//
// The offer here is signed by a key its named exchange does not publish, which
// is what a substituted or tampered offer looks like from this side. Three
// assertions, and the second is the one that matters most: it must not appear
// among the offers, because an offer an agent can see is an offer it can try to
// buy.
func TestDiscover_UnverifiableOfferIsRejectedNotReturned(t *testing.T) {
	f := newFixture(t)

	// Signed by a key that is not the issuer's. The exchange field still names
	// the real issuer, so the key resolves — and the signature then fails against
	// it, which is the tampered-offer shape rather than the unknown-issuer one.
	_, strangerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate stranger key: %v", err)
	}
	doctored := f.issuer.Offer(t, "offer-doctored")
	resigned, err := helpers.SignOffer(strangerPriv, doctored)
	if err != nil {
		t.Fatalf("re-sign offer: %v", err)
	}
	doctored.Signature = resigned

	genuine := f.issuer.Offer(t, "offer-genuine")
	f.broker.resolveResp = &rampv1.DiscoveryResponse{
		Ver: helpers.ProtocolVersion,
		OfferGroups: []*rampv1.OfferGroup{{
			Uri:    "https://pub.example/a",
			Offers: []*rampv1.Offer{genuine, doctored},
		}},
	}
	a := f.provision(t, "dev-one")

	out := callTool[discoverResult](t, f.connect(t, a.Token), "ramp_discover", map[string]any{
		"uris": []string{"https://pub.example/a"},
	})

	if len(out.OfferGroups) != 1 {
		t.Fatalf("got %d offer groups, want 1", len(out.OfferGroups))
	}
	group := out.OfferGroups[0]

	// The genuine one survives, so this is not "verification refused everything".
	if len(group.Offers) != 1 {
		t.Fatalf("got %d offers, want only the genuine one: %+v", len(group.Offers), group.Offers)
	}
	if group.Offers[0]["offer_id"] != "offer-genuine" {
		t.Errorf("surviving offer = %v, want offer-genuine", group.Offers[0]["offer_id"])
	}

	// The doctored one is NOT among them. An offer an agent can see is one it can
	// hand back to be bought, and nothing on the purchase path re-checks it.
	for _, o := range group.Offers {
		if o["offer_id"] == "offer-doctored" {
			t.Fatal("the doctored offer was returned as licensable")
		}
	}

	// It is visible, with a reason. Silence would leave the agent unable to tell
	// a thin catalog from a signature that did not check out.
	if len(group.Rejected) != 1 {
		t.Fatalf("got %d rejections, want 1: %+v", len(group.Rejected), group.Rejected)
	}
	if got := group.Rejected[0].OfferID; got != "offer-doctored" {
		t.Errorf("rejected offer_id = %q, want offer-doctored", got)
	}
	if got := group.Rejected[0].Reason; got != "signature_invalid" {
		t.Errorf("rejected reason = %q, want signature_invalid", got)
	}
}

// TestDiscover_RejectionNamesTheCause drives the three refusal causes the token
// vocabulary promises but the test above does not reach.
//
// Each token is a value an agent branches on, and a wrong one costs the agent the
// action it would have taken: an expired offer means ask again, an unresolvable
// issuer means this exchange is misconfigured, extra fields mean this service's
// protocol pin is behind. All three used to arrive as the same word — the one
// reserved for a cause nobody could name — and no assertion anywhere noticed,
// because every case still produced a token.
//
// The signature case is not repeated here. It has its own test above, which
// asserts more than the token: that the offer is withheld from the agent
// entirely.
func TestDiscover_RejectionNamesTheCause(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	// An origin that is named but answers nothing. Started and closed at once so
	// the address stays valid to write into an offer while the dial is refused
	// immediately — a hostname that resolves nowhere would wait out a DNS lookup
	// instead, and the test would be slow for a reason unrelated to what it pins.
	dead := httptest.NewServer(http.NotFoundHandler())
	deadDomain := hostOf(t, dead.URL)
	dead.Close()

	unknownIssuer := f.issuer.Offer(t, "offer-unknown-issuer")
	unknownIssuer.Exchange = deadDomain

	tests := []struct {
		name  string
		offer *rampv1.Offer
		want  string
	}{
		{
			name:  "the expiry has already passed",
			offer: f.issuer.OfferAt(t, "offer-stale", time.Now().Add(-time.Minute)),
			want:  "offer_expired",
		},
		{
			name:  "the issuing exchange publishes no directory",
			offer: unknownIssuer,
			want:  "issuer_key_unresolved",
		},
		{
			name:  "the offer carries a field this build cannot render",
			offer: withUnknownField(t, f.issuer.Offer(t, "offer-newer-protocol")),
			want:  "unknown_fields",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			f.broker.resolveResp = &rampv1.DiscoveryResponse{
				Ver: helpers.ProtocolVersion,
				OfferGroups: []*rampv1.OfferGroup{{
					Uri:    "https://pub.example/a",
					Offers: []*rampv1.Offer{tc.offer},
				}},
			}

			out := callTool[discoverResult](t, f.connect(t, a.Token), "ramp_discover", map[string]any{
				"uris": []string{"https://pub.example/a"},
			})

			if len(out.OfferGroups) != 1 {
				t.Fatalf("got %d offer groups, want 1", len(out.OfferGroups))
			}
			group := out.OfferGroups[0]
			if len(group.Offers) != 0 {
				t.Errorf("a refused offer was returned as licensable: %+v", group.Offers)
			}
			if len(group.Rejected) != 1 {
				t.Fatalf("got %d rejections, want 1: %+v", len(group.Rejected), group.Rejected)
			}
			if got := group.Rejected[0].Reason; got != tc.want {
				t.Errorf("reason = %q, want %q", got, tc.want)
			}
		})
	}
}

// withUnknownField returns offer carrying bytes this build's protocol does not
// declare, the way an offer minted by a peer running a newer protocol arrives.
//
// It is built by appending to the encoded form rather than by setting a field,
// because there is no field to set: the whole point is a number this build has
// never heard of. The signature is left as it was — an offer whose canonical
// bytes cannot be rendered is refused before the signature is ever checked, and
// that ordering is what the test using this asserts.
func withUnknownField(t *testing.T, offer *rampv1.Offer) *rampv1.Offer {
	t.Helper()
	raw, err := proto.Marshal(offer)
	if err != nil {
		t.Fatalf("marshal offer: %v", err)
	}
	// A field number far above anything the protocol assigns, so this cannot
	// start meaning something when the schema grows.
	raw = protowire.AppendTag(raw, 9999, protowire.BytesType)
	raw = protowire.AppendBytes(raw, []byte("from a newer protocol"))

	var out rampv1.Offer
	if err := proto.Unmarshal(raw, &out); err != nil {
		t.Fatalf("unmarshal offer with an unknown field: %v", err)
	}
	return &out
}

// TestDiscover_OfferNamingAPathIsRefusedBeforeAnythingIsFetched pins that an
// exchange domain which is not a plain host is refused, and refused before the
// request it would shape is sent.
//
// The value comes off an offer a Broker relayed and nothing has vetted it — the
// fetch it drives exists in order to find out whether that offer is genuine, so
// there is no earlier point at which it could have been trusted. The directory
// URL is built by concatenating it, so a domain carrying a path chooses the URL
// this service fetches, not merely the host it fetches from: one blind GET to a
// caller-chosen address per offer in a discovery response. The address guard has
// no objection, because the address is fine.
//
// Both halves are asserted. The offer is refused, AND the host named in it
// received nothing — a refusal that still dialled would leave the request this
// exists to prevent already sent.
func TestDiscover_OfferNamingAPathIsRefusedBeforeAnythingIsFetched(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	// The issuer's own host, with a path appended. Everything about the address
	// is legitimate; only the shape of the value is not.
	probing := f.issuer.Offer(t, "offer-probing")
	probing.Exchange = f.issuer.Domain(t) + "/probe"

	f.broker.resolveResp = &rampv1.DiscoveryResponse{
		Ver: helpers.ProtocolVersion,
		OfferGroups: []*rampv1.OfferGroup{{
			Uri:    "https://pub.example/a",
			Offers: []*rampv1.Offer{probing},
		}},
	}
	before := f.issuer.HTTPRequests()

	out := callTool[discoverResult](t, f.connect(t, a.Token), "ramp_discover", map[string]any{
		"uris": []string{"https://pub.example/a"},
	})

	if len(out.OfferGroups) != 1 {
		t.Fatalf("got %d offer groups, want 1", len(out.OfferGroups))
	}
	group := out.OfferGroups[0]
	if len(group.Offers) != 0 {
		t.Errorf("an offer naming a path was returned as licensable: %+v", group.Offers)
	}
	if len(group.Rejected) != 1 {
		t.Fatalf("got %d rejections, want 1: %+v", len(group.Rejected), group.Rejected)
	}
	if got := group.Rejected[0].Reason; got != "issuer_key_unresolved" {
		t.Errorf("reason = %q, want issuer_key_unresolved", got)
	}
	// Counted on ANY path, not just the directory's. Without the check the URL
	// this service builds carries the smuggled path, so the request lands
	// somewhere the mux does not serve — which a per-document counter would miss
	// while the request it exists to prevent had already been sent.
	if got := f.issuer.HTTPRequests() - before; got != 0 {
		t.Errorf("the named host received %d requests; a refused domain must be dialled zero times", got)
	}
}

// TestDiscover_CustodyFailureIsNamedNotSignable pins that a call this service
// could not sign says so.
//
// The agent's key is custodied, so every outbound RAMP call depends on a backend
// that can be down. That failure is local — nothing left the process, no peer
// refused anything — and it is the one an operator alerts on, because it means
// every agent is failing at once rather than one agent's request being wrong.
// Reported as the unclassified token it is indistinguishable from a peer that
// answered something unreadable, and an alert keyed on it stays silent.
//
// Custody genuinely goes away here rather than being faked: the shared mount is
// torn down and rebuilt, which is the same reset every test in this package runs
// at its start.
//
// The DELIVERY leg's version of this is not reachable through this surface, and
// that is worth saying rather than leaving to be noticed. A purchase signs with
// the same key source as the fetch that follows it, so custody failing takes the
// purchase down first — which is the test below — and the call never reaches
// delivery. Driving that one would need custody to fail between the two, which
// only a seam built for the test could arrange.
func TestDiscover_CustodyFailureIsNamedNotSignable(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	if err := sharedVault.Reset(t.Context()); err != nil {
		t.Fatalf("tear custody down: %v", err)
	}

	msg := callToolErr(t, session, "ramp_discover", map[string]any{
		"uris": []string{"https://pub.example/a"},
	})

	if msg == "" {
		t.Fatal("discovery succeeded with no signing key available")
	}
	if !strings.Contains(msg, "not_signable") {
		t.Errorf("tool error %q, want it to name the call as unsignable", msg)
	}
	// Nothing was sent. A request that could not be signed must not reach a peer
	// unsigned, and the Broker's middleware would refuse it anyway — which is
	// exactly why the count has to be the broad one. Calls() records what passed
	// that middleware, so a regression that sent the unsigned request would leave
	// it at zero while the request had already gone; HTTPRequests() counts what
	// arrived, refused or served.
	if n := f.broker.HTTPRequests(); n != 0 {
		t.Errorf("the Broker received %d requests; an unsignable request leaves no process", n)
	}
}

// TestExecute_CustodyFailureIsNamedAndSaysNothingAboutTheStore drives the same
// custody outage through the PURCHASE leg, which is a different code path and
// the one that matters most.
//
// The purchase does not go through the SDK — it is a raw POST to the Broker's
// relay route — so it classified the same failure as unreachable with no typed
// detail, and the agent got prose with no token. An operator alert keyed on the
// class was therefore silent on the one leg where money moves, while firing on
// the other three.
//
// The second assertion is that the agent gets a FIXED sentence rather than the
// cause. Every branch of the key store's classifier preserves the error
// underneath it, so a custody outage that is a transport failure arrives
// carrying the store's own URL — host, port and secret path — and that text is
// what a client forwards into its own logs, which outlive the request.
//
// What this fixture produces is a logical miss, not a transport failure: the
// mount is torn down and rebuilt, so the store answers "no active key" and no
// address appears in it either way. So the assertion is on the sentence, which
// IS demonstrable here — without the redaction the agent receives the raw chain
// down to the keystore package name. The host check below it is a tripwire for
// the transport-failure case, which this surface cannot reach while the shared
// Vault stays up for the rest of the package.
func TestExecute_CustodyFailureIsNamedAndSaysNothingAboutTheStore(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)

	vaultHost := hostOf(t, sharedVault.Client.Address())
	if err := sharedVault.Reset(t.Context()); err != nil {
		t.Fatalf("tear custody down: %v", err)
	}

	msg := callToolErr(t, session, "ramp_execute", map[string]any{
		"offers": []map[string]any{signedOffer("offer-1", "exchange.example")},
	})

	if msg == "" {
		t.Fatal("the purchase succeeded with no signing key available")
	}
	if !strings.Contains(msg, "not_signable") {
		t.Errorf("tool error %q, want it to name the call as unsignable", msg)
	}
	if !strings.Contains(msg, "signing key could not be produced") {
		t.Errorf("tool error %q, want the fixed sentence rather than the cause", msg)
	}
	if strings.Contains(msg, "keystore:") || strings.Contains(msg, vaultHost) {
		t.Errorf("tool error describes this service's own key store: %s", msg)
	}
	// Nothing was sent, counted the same way and for the same reason as on the
	// discovery leg.
	if n := f.broker.HTTPRequests(); n != 0 {
		t.Errorf("the Broker received %d requests; an unsignable request leaves no process", n)
	}
}

// TestAccountLegs_CustodyFailureIsClassedAndTheCauseGoesToTheLog drives the same
// custody outage through the two tools that resolve no key of their own.
//
// Register and status hand the resolution to the signing transport, so the
// failure surfaces from inside RoundTrip: net/http wraps it in a *url.Error and
// the Connect client wraps that again, and by the time it reaches the boundary
// no type names the condition any more. Both tools therefore answered with a
// transport code — the peer's vocabulary for a fault that never left this
// process — and handed the agent the key store's own diagnostics. The three
// legs that resolve their key before building a request had neither problem,
// which is what made the gap easy to miss.
//
// The second half is the separation the redaction depends on and nothing
// proved: the agent gets a fixed sentence, the operator's log keeps the cause.
// Both are asserted here on ONE call, because a claim that two texts differ
// cannot be checked by reading either alone.
//
// Same fixture limit as the purchase-leg test above: tearing the mount down
// produces a logical miss, so no address appears in the cause either way. The
// sentence is the demonstrable half; the host check is a tripwire for the
// transport failure this surface cannot reach while the shared Vault stays up
// for the rest of the package.
func TestAccountLegs_CustodyFailureIsClassedAndTheCauseGoesToTheLog(t *testing.T) {
	for _, tool := range []string{"ramp_status", "ramp_register"} {
		t.Run(tool, func(t *testing.T) {
			f := newFixture(t)
			a := f.provision(t, "dev-one")
			session := f.connect(t, a.Token)
			// Both tools are driven at a NAMED Exchange. ramp_status without one
			// answers from a local note and signs nothing, so it could not reach a
			// custody failure at all — driving that mode here would assert against
			// a path the test is not about.
			// ramp_register carries the payload; ramp_status takes the domain
			// alone. Both start from the same well-formed arguments so a refusal
			// here is the custody failure and not a local pre-check.
			args := registerArgs(t, f)
			if tool == "ramp_status" {
				delete(args, "fields")
			}

			vaultHost := hostOf(t, sharedVault.Client.Address())
			if err := sharedVault.Reset(t.Context()); err != nil {
				t.Fatalf("tear custody down: %v", err)
			}

			msg := callToolErr(t, session, tool, args)

			if msg == "" {
				t.Fatalf("%s succeeded with no signing key available", tool)
			}
			if !strings.Contains(msg, "not_signable") {
				t.Errorf("tool error %q, want it to name the call as unsignable", msg)
			}
			if !strings.Contains(msg, "signing key could not be produced") {
				t.Errorf("tool error %q, want the fixed sentence rather than the cause", msg)
			}
			if strings.Contains(msg, "keystore:") || strings.Contains(msg, vaultHost) {
				t.Errorf("tool error describes this service's own key store: %s", msg)
			}

			// The other half. The operator loses nothing the agent was not told —
			// the cause the message dropped is on the line, named by the tool that
			// failed.
			lines := f.logs.Find("identity.mcp.call_failed")
			if len(lines) != 1 {
				t.Fatalf("got %d call_failed lines, want 1: %v", len(lines), lines)
			}
			if !strings.Contains(lines[0], `"op":"`+tool+`"`) {
				t.Errorf("log line %s, want it to name the failed tool", lines[0])
			}
			if !strings.Contains(lines[0], "keystore:") {
				t.Errorf("log line %s, want it to keep the cause the agent was not given", lines[0])
			}
		})
	}
}

// TestReport_RefusesEndpointOnAnotherPort pins the port half of the endpoint
// rule, which the host half alone does not cover.
//
// A manifest may advertise an endpoint on the host AND port that served it, or a
// subdomain of that host. The port is part of the match because a different port
// is a different service — one the party that published the manifest need not
// control, and one a dial-time address guard has no objection to, since the
// address is the same. Without this, an Exchange sharing a host with anything
// else could redirect an agent-signed usage report to its neighbour.
//
// The same-host test beside this one would pass against an implementation that
// compared hostnames only, which is what makes this its own case.
func TestReport_RefusesEndpointOnAnotherPort(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	// A second origin on the SAME host, differing only in port — the case the
	// hostname comparison cannot see.
	neighbour := newRAMPPeer(t, f.trust)
	if neighbour.Domain(t) == f.issuer.Domain(t) {
		t.Fatal("the two peers share a host:port; the fixture cannot tell the ports apart")
	}
	f.issuer.setManifestEndpoint(neighbour.URL())

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_report", map[string]any{
		"exchange":        f.issuer.Domain(t),
		"transaction_id":  "tx-port",
		"idempotency_key": "idem-report-port",
	})

	if msg == "" {
		t.Fatal("a report to an endpoint on another port was accepted")
	}
	// Asserted on the TOKEN, not on the sentence. The words in the message are
	// the SDK's, so a rewording upstream would turn a prose assertion red for no
	// behavioural reason — and "refused" is also how a dial failure reads, which
	// is the outcome this test exists to tell apart from an endpoint refusal.
	// not_sent is the class the SDK gives a call it declined to make.
	if !strings.Contains(msg, "not_sent") {
		t.Errorf("tool error %q, want it to carry the not_sent class", msg)
	}
	// Counted on ANY path. Calls() records only what passed the peer's signature
	// gate and reached a registered handler, so a request that arrived and was
	// refused there, or landed on a path its mux does not serve, would leave it at
	// zero while the report had already left this process. The neighbour serves no
	// document this call reads, so its broad count is zero unless something was
	// sent to it.
	if n := neighbour.HTTPRequests(); n != 0 {
		t.Errorf("the neighbouring port received %d requests; a refused report must reach no one", n)
	}
}
