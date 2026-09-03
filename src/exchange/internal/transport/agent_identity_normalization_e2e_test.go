//go:build integration

package transport_test

import (
	"testing"

	connect "connectrpc.com/connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/testutil"
)

// An agent's identity is the HOST of the directory it names in the covered
// Signature-Agent header, not the URL verbatim. The scheme is a property of the
// deployment — compose serves directories over http, production over https — so
// letting it into the identity gave one agent several registrations, each with its
// own key pin and its own billing account.
//
// These drive the property through the public Connect router only: Register
// creates the account, GetAccountStatus reads it back. Both legs traverse
// transport → service → repo → Postgres, and the account is observed through the
// same RPC a client would use, so no test here reaches past a layer (Testing
// Doctrine §9). The billing_ref is the observable: it is minted once per account,
// so two spellings returning one ref is proof they resolved to one row, and it
// comes from the stored row rather than anything the caller sent.
//
// The harness reuses newRegisterHarness / newAgent wholesale; only the
// Signature-Agent the client signs with varies, which is exactly the variable
// under test.

// TestAgentIdentity_SchemeSpellingsShareOneAccount is the ticket's property. One
// agent, one key, three spellings of its directory: the bare host it self-signed
// up under, and the same host with each scheme. All three must land on the account
// the first call created.
//
// Without normalization the https and http calls would each miss the row keyed on
// the bare host and self-sign up a second and third time, so each would report its
// own freshly-minted billing_ref — the assertion below would see three different
// refs where the agent has one account.
func TestAgentIdentity_SchemeSpellingsShareOneAccount(t *testing.T) {
	h := newRegisterHarness(t)
	const host = "collapse-agent.example"
	a := h.newAgent(t, host)

	reg, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(testutil.RegistrationStruct(t, map[string]any{"legal_entity": "Collapse AI Ltd"}))))
	if err != nil {
		t.Fatalf("Register as bare host %q: %v", host, err)
	}
	want := reg.Msg.GetBillingRef()
	if want == "" {
		t.Fatal("Register returned an empty billing_ref; the rest of this test would assert nothing")
	}

	// The SAME key, re-signed under each schemed spelling of the same directory.
	for _, directory := range []string{"https://" + host, "http://" + host, host} {
		t.Run(directory, func(t *testing.T) {
			client := h.clientFor(directory, a.priv)
			resp, err := client.GetAccountStatus(h.ctx,
				connect.NewRequest(newAccountStatusRequest()))
			if err != nil {
				t.Fatalf("GetAccountStatus signing Signature-Agent %q: %v", directory, err)
			}
			if got := resp.Msg.GetBillingRef(); got != want {
				t.Errorf("billing_ref = %q, want %q — %q resolved to a different account than %q",
					got, want, directory, host)
			}
			if !resp.Msg.GetActive() {
				t.Error("active = false, want true (the account Register created)")
			}
		})
	}
}

// TestAgentIdentity_SchemeIsNotAnIdentityBoundary is the same property seen from
// the other side, and it is the one that matters for authorization: a caller must
// not be able to pick which identity it registers as by choosing a scheme. Here
// the FIRST contact is over https and the follow-up is bare, so the row is created
// from a schemed directory and read back without one. Registering twice would mint
// a second billing_ref; sharing the account is what proves the scheme never
// reached the stored key.
func TestAgentIdentity_SchemeIsNotAnIdentityBoundary(t *testing.T) {
	h := newRegisterHarness(t)
	const host = "https-first-agent.example"
	a := h.newAgent(t, host)

	// Self-sign up and register under the https spelling.
	httpsClient := h.clientFor("https://"+host, a.priv)
	reg, err := httpsClient.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("Register as %q: %v", "https://"+host, err)
	}
	want := reg.Msg.GetBillingRef()

	// A second Register under the bare spelling must be the already-registered fast
	// path returning the SAME ref, not a fresh account (ADR-021 D4: the stored id
	// wins). A new ref here would mean the bare spelling is a separate identity.
	again, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("Register as bare %q after registering as https: %v", host, err)
	}
	if got := again.Msg.GetBillingRef(); got != want {
		t.Fatalf("billing_ref = %q, want %q — the bare spelling minted a second account", got, want)
	}
}

// TestAgentIdentity_QuotedSignatureAgentAuthorizes is the interop half of the
// ticket, driven end to end. Web Bot Auth defines the Signature-Agent value as an
// RFC 8941 String, and a String has exactly one serialization — quoted — so this
// is what a conformant external agent puts on the wire:
//
//	Signature-Agent: "https://agent.example"
//
// Read verbatim, the quotes travel into the directory URI, no host parses out of
// it, the signer's key is never found, and the request is refused. That made a
// spec-conformant agent unable to talk to the Exchange at all — a 401, not a
// cosmetic storage-format wart.
//
// This could not be written until the SDK pin moved: the Connect gate verifies
// through the SDK, so before that the quoted form was rejected no matter what the
// app did. It is also the assertion that proves the two halves of the fix meet —
// the SDK unquotes the value, and internal/agentid reduces it to the host that
// keys the account.
func TestAgentIdentity_QuotedSignatureAgentAuthorizes(t *testing.T) {
	h := newRegisterHarness(t)
	const host = "quoted-agent.example"
	a := h.newAgent(t, host)

	// Register with the bare form the agent self-signed up under.
	reg, err := a.client.Register(h.ctx, connect.NewRequest(newRegisterRequest(nil)))
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	want := reg.Msg.GetBillingRef()

	// The same key, now signing the quoted form a conformant agent sends. The
	// header is signed WITH its quotes — the signature base covers the wire bytes —
	// and only the extracted directory is unquoted.
	quoted := h.clientFor(`"https://`+host+`"`, a.priv)
	resp, err := quoted.GetAccountStatus(h.ctx,
		connect.NewRequest(newAccountStatusRequest()))
	if err != nil {
		t.Fatalf(`GetAccountStatus signing Signature-Agent "https://%s": %v — a conformant signer must not be refused`, host, err)
	}
	if got := resp.Msg.GetBillingRef(); got != want {
		t.Errorf("billing_ref = %q, want %q — the quoted form resolved to a different account than the bare one",
			got, want)
	}
}

// TestAgentIdentity_UnusableDirectoryIsRejected is the negative path (Testing
// Doctrine §10). A Signature-Agent that names no host cannot be an identity and
// cannot be a fetch target, so it must be refused rather than stored.
//
// The value used is the spec's sf-dictionary form, which RAMP deliberately does
// not read — an inline data: member would let a signer supply its own key
// directory, and key resolution rests on fetching the directory from a location
// the signer had to control. It is also a stable choice for this assertion: unlike
// the quoted sf-string, no layer unwraps it, so this test pins the refusal rather
// than a parsing gap that a later change would close.
//
// The refused call is a REGISTER, deliberately, and that choice is what makes the
// side-effect half of this test able to fail at all. Register is the only RPC that
// mints a billing_ref; GetAccountStatus answers NotFound for any row without one
// and lazily creates the row it reads. So a refused GetAccountStatus leaves
// "no account exists" true no matter what the code does — it asserts nothing. A
// refused Register leaves it true only while the refusal actually holds: an
// over-lenient parser that unwrapped the dictionary form would mint a ref under
// the bare host, and the follow-up below would find it.
func TestAgentIdentity_UnusableDirectoryIsRejected(t *testing.T) {
	h := newRegisterHarness(t)
	const host = "dict-form-agent.example"
	a := h.newAgent(t, host)

	client := h.clientFor(`agent2="https://`+host+`"`, a.priv)
	_, err := client.Register(h.ctx, connect.NewRequest(newRegisterRequest(testutil.RegistrationStruct(t, map[string]any{"legal_entity": "Dict Form AI Ltd"}))))
	if err == nil {
		t.Fatal("Register succeeded with a Signature-Agent that names no host; want rejection")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("code = %v, want Unauthenticated (err=%v)", got, err)
	}

	// No account was created for the host named INSIDE the refused value. Observed
	// through the public read RPC: NotFound is the answer for an agent with no
	// billing_ref, and only Register mints one.
	_, err = a.client.GetAccountStatus(h.ctx,
		connect.NewRequest(newAccountStatusRequest()))
	if got := connect.CodeOf(err); got != connect.CodeNotFound {
		t.Fatalf("code = %v, want NotFound — the refused Register minted an account for %q anyway (err=%v)",
			got, host, err)
	}
}
