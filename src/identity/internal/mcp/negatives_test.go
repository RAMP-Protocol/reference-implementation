//go:build integration

package mcp_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
	identitymcp "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/mcp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/token"
)

// The bearer negatives all assert the SAME two things: the endpoint refuses the
// caller, AND no RAMP request went out. The second half is the one worth having.
// A gate that rejected the caller only after signing and sending would have leaked
// an authenticated action on an unauthenticated request — and every
// response-shape assertion would still pass.

func TestBearer_MissingTokenIsRefusedBeforeAnyRAMPCall(t *testing.T) {
	f := newFixture(t)
	f.provision(t, "dev-one")

	assertUnauthorized(t, f, "")
}

func TestBearer_GarbageTokenIsRefusedBeforeAnyRAMPCall(t *testing.T) {
	f := newFixture(t)
	f.provision(t, "dev-one")

	assertUnauthorized(t, f, "not-a-jwt")
}

// A token this service did not sign must not open the endpoint, however
// well-formed it is. The forged issuer mints the same claims with its own key.
func TestBearer_ForeignlySignedTokenIsRefused(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	forger, err := token.NewIssuer(newTokenKey(t), authIssue, tokenAudience, systemClock())
	if err != nil {
		t.Fatalf("token.NewIssuer: %v", err)
	}
	forged, err := forger.Mint(a.Subdomain, tokenTTL)
	if err != nil {
		t.Fatalf("mint forged token: %v", err)
	}

	assertUnauthorized(t, f, forged)
}

// A token minted for a different resource must not open this one. Audience is
// what stops a token issued for some other service being replayed here.
func TestBearer_WrongAudienceIsRefused(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	other, err := token.NewIssuer(newTokenKey(t), authIssue, "http://elsewhere.example", systemClock())
	if err != nil {
		t.Fatalf("token.NewIssuer: %v", err)
	}
	wrong, err := other.Mint(a.Subdomain, tokenTTL)
	if err != nil {
		t.Fatalf("mint token: %v", err)
	}

	assertUnauthorized(t, f, wrong)
}

func TestBearer_ExpiredTokenIsRefused(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	expired, err := f.tokens.Mint(a.Subdomain, -time.Minute)
	if err != nil {
		t.Fatalf("mint expired token: %v", err)
	}

	assertUnauthorized(t, f, expired)
}

// The 401 must point the client at the metadata document, or an MCP client has no
// way to discover where to sign in. RFC 9728 §5.1.
func TestBearer_ChallengeAdvertisesTheMetadataDocument(t *testing.T) {
	f := newFixture(t)

	resp := postMCP(t, f, "")
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	challenge := resp.Header.Get("WWW-Authenticate")
	if !strings.Contains(challenge, "resource_metadata=") {
		t.Fatalf("WWW-Authenticate = %q, want a resource_metadata pointer", challenge)
	}
	if !strings.Contains(challenge, identitymcp.ProtectedResourceMetadataPath) {
		t.Fatalf("WWW-Authenticate = %q, want it to name %s",
			challenge, identitymcp.ProtectedResourceMetadataPath)
	}
}

// The metadata document itself must be reachable WITHOUT a token — a client fetches
// it precisely because it does not have one yet — and must advertise the audience
// tokens are actually minted for.
func TestProtectedResourceMetadata_IsPublicAndNamesTheIssuer(t *testing.T) {
	f := newFixture(t)

	resp, err := http.Get(f.srv.URL + identitymcp.ProtectedResourceMetadataPath)
	if err != nil {
		t.Fatalf("fetch metadata: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 without any bearer", resp.StatusCode)
	}
	var md struct {
		Resource             string   `json:"resource"`
		AuthorizationServers []string `json:"authorization_servers"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&md); err != nil {
		t.Fatalf("decode metadata: %v", err)
	}
	if md.Resource != tokenAudience {
		t.Errorf("resource = %q, want the audience tokens carry (%q)", md.Resource, tokenAudience)
	}
	if len(md.AuthorizationServers) != 1 || md.AuthorizationServers[0] != authIssue {
		t.Errorf("authorization_servers = %v, want [%s]", md.AuthorizationServers, authIssue)
	}
}

// A RAMP-side refusal must reach the agent as a failed tool call carrying the
// TYPED reason, not as a bare transport code. An agent branches on the reason; a
// message saying only "permission denied" tells it nothing it can act on.
func TestRAMPRefusal_SurfacesTheTypedReason(t *testing.T) {
	f := newFixture(t)
	// A refusal carrying a real ErrorDetail — which is what makes this test about
	// the TYPED reason. Without an attached detail the tool error is satisfied
	// entirely by the transport-code fallback, and deleting the whole typed path
	// would leave the suite green. That case is worth pinning too; it is
	// TestRAMPRefusal_FallsBackToTheTransportCode below.
	refusal := connect.NewError(connect.CodePermissionDenied,
		errStub("agent is not permitted to register"))
	refusal.AddDetail(mustDetail(t, &rampv1.ErrorDetail{
		Reason: &rampv1.ErrorDetail_RegistrationFailure{
			RegistrationFailure: &rampv1.RegistrationFailure{
				Reason: rampv1.RegistrationFailureReason_REGISTRATION_FAILURE_REASON_DOMAIN_NOT_VERIFIED,
			},
		},
	}))
	f.exchange.failWith(refusal)
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_register", registerArgs(t, f))

	// The enum NAME, not the transport code: an agent branches on the reason, and
	// "permission denied" does not say which of several refusals happened.
	if !strings.Contains(msg, "REGISTRATION_FAILURE_REASON_DOMAIN_NOT_VERIFIED") {
		t.Errorf("tool error %q, want it to carry the typed registration-failure reason", msg)
	}
	if !strings.Contains(msg, "not permitted to register") {
		t.Errorf("tool error %q, want it to carry the Exchange's message", msg)
	}
}

// The companion to the test above: a refusal with NO detail must still surface,
// falling back to the transport code. Split out so each test pins one branch —
// together they cover both arms of rampError.
func TestRAMPRefusal_FallsBackToTheTransportCode(t *testing.T) {
	f := newFixture(t)
	f.exchange.failWith(connect.NewError(connect.CodePermissionDenied,
		errStub("agent is not permitted to register")))
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_register", registerArgs(t, f))

	if !strings.Contains(msg, "permission_denied") {
		t.Errorf("tool error %q, want it to carry the transport code", msg)
	}
	if !strings.Contains(msg, "not permitted to register") {
		t.Errorf("tool error %q, want it to carry the Exchange's message", msg)
	}
}

// mustDetail wraps a protobuf message as a Connect error detail.
func mustDetail(t *testing.T, msg *rampv1.ErrorDetail) *connect.ErrorDetail {
	t.Helper()
	d, err := connect.NewErrorDetail(msg)
	if err != nil {
		t.Fatalf("connect.NewErrorDetail: %v", err)
	}
	return d
}

// A tool that needs arguments must reject a request that omits them, before any
// outbound call: an empty discovery has nothing to ask the Broker about.
func TestDiscover_RequiresUrisOrQuery(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_discover", map[string]any{})

	if !strings.Contains(msg, "uri") {
		t.Errorf("tool error %q, want it to name the missing argument", msg)
	}
	if len(f.broker.Calls()) != 0 {
		t.Error("an argument-less discovery still reached the Broker")
	}
}

// Reporting without an idempotency key is refused rather than quietly minted for
// the caller: a key we invent per call makes every retry a fresh report, which is
// the double-counting the field exists to prevent.
func TestReport_RequiresAnIdempotencyKey(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")

	msg := callToolErr(t, f.connect(t, a.Token), "ramp_report", map[string]any{
		"exchange":       "exchange.example",
		"transaction_id": "tx-1",
	})

	if !strings.Contains(msg, "idempotency_key") {
		t.Errorf("tool error %q, want it to name the missing idempotency_key", msg)
	}
	if len(f.exchange.Calls()) != 0 {
		t.Error("a report with no idempotency key still reached the Exchange")
	}
}

// TestReport_RefusesAnExchangeThatIsNotABareDomain drives the SSRF refusal on the
// report leg's FIRST hop — the unsigned manifest fetch, which happens before the
// host anchor gets a say.
//
// The endpoint resolver builds {scheme}://{exchange}/.well-known/ramp.json by
// concatenation, so an `exchange` carrying a path, query or fragment makes the
// caller the author of the whole URL this service fetches, not just of the host.
// A fragment is the sharpest form: everything after it is discarded, so
// "host/internal/admin?token=x#" fetches /internal/admin and the well-known
// suffix never appears.
//
// Each case asserts BOTH halves — the call is refused, and the manifest was never
// fetched. The fetch count is the load-bearing assertion: a refusal that happened
// after the request went out would prevent nothing.
// The cases come from the shared table, rendered against the issuer's REAL host,
// so each one names a host that would have answered. The account tools and the
// allowlist parser drive the same table, which is what makes a rule that started
// admitting one of these show up in three places rather than one. One fixture
// serves them all: every case must leave the fetch count at zero, so a
// cumulative zero at the end is the same assertion made once per case and is not
// weakened by sharing.
func TestReport_RefusesAnExchangeThatIsNotABareDomain(t *testing.T) {
	f := newFixture(t)
	a := f.provision(t, "dev-one")
	session := f.connect(t, a.Token)
	host := f.issuer.Domain(t)

	for _, tc := range testutil.NonBareDomains {
		t.Run(tc.Name, func(t *testing.T) {
			msg := callToolErr(t, session, "ramp_report", map[string]any{
				"exchange":        tc.Of(host),
				"transaction_id":  "tx-1",
				"idempotency_key": "idem-report-1",
			})

			if !strings.Contains(msg, "bare domain") {
				t.Errorf("tool error %q, want it to name the bare-domain requirement", msg)
			}
		})
	}

	if n := f.issuer.ManifestFetches(); n != 0 {
		t.Errorf("the well-known document was fetched %d times; a URL the caller "+
			"composed must never be dialed", n)
	}
	if n := len(f.issuer.Calls()); n != 0 {
		t.Errorf("the Exchange received %d calls; every report was refused before sending", n)
	}
}

// --- helpers ---

// assertUnauthorized drives a raw MCP POST with the given bearer and requires both
// halves of the property: 401 back, and nothing sent onward to any RAMP peer.
func assertUnauthorized(t *testing.T, f *fixture, bearer string) {
	t.Helper()
	resp := postMCP(t, f, bearer)
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	if n := len(f.exchange.Calls()); n != 0 {
		t.Errorf("the Exchange saw %d calls; an unauthenticated request must not be signed or sent", n)
	}
	if n := len(f.broker.Calls()); n != 0 {
		t.Errorf("the Broker saw %d calls; an unauthenticated request must not be signed or sent", n)
	}
}

// postMCP sends a raw tools/call to the endpoint, bypassing the MCP client so the
// rejected-handshake cases are observable as an HTTP status. The SDK client would
// fail the connect instead, hiding the status and the challenge header.
func postMCP(t *testing.T, f *fixture, bearer string) *http.Response {
	t.Helper()
	body := strings.NewReader(
		`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"ramp_status","arguments":{}}}`,
	)
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost,
		f.srv.URL+identitymcp.EndpointPath, body)
	if err != nil {
		t.Fatalf("new request: %v", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post to the MCP endpoint: %v", err)
	}
	return resp
}

// callToolErr runs a tools/call expected to fail and returns the reported message.
func callToolErr(
	t *testing.T, session *mcpsdk.ClientSession, name string, args map[string]any,
) string {
	t.Helper()
	res, err := session.CallTool(t.Context(), &mcpsdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		// A protocol-level failure (e.g. schema validation) is also a refusal;
		// report its text so the assertion can inspect it either way.
		return err.Error()
	}
	if !res.IsError {
		t.Fatalf("call %s succeeded; want a refusal", name)
	}
	return textOf(res)
}

// textOf renders a tool result's unstructured content, which is where a failed
// call's message lands.
func textOf(res *mcpsdk.CallToolResult) string {
	var sb strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcpsdk.TextContent); ok {
			sb.WriteString(tc.Text)
		}
	}
	return sb.String()
}

// decodeStructured re-decodes a tool's structured result into out, so assertions
// read the JSON the agent actually received rather than a Go value the test
// happened to construct.
func decodeStructured(t *testing.T, res *mcpsdk.CallToolResult, out any) {
	t.Helper()
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("decode structured content %s: %v", raw, err)
	}
}

// errStub is a minimal error carrying a fixed message.
type errStub string

func (e errStub) Error() string { return string(e) }
