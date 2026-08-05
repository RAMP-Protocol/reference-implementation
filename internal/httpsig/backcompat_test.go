package httpsig

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
)

// Frozen fixture: a 2-signature forwarding chain produced by the earlier
// hand-rolled signer, whose @signature-params used the param order
// keyid;alg;created;expires. The swap to yaronf/httpsign emits
// created;expires;alg;keyid. These constants are the exact bytes the old code
// put on the wire (captured from internal/httpsig@origin/v1.1 with fixed seeds).
const (
	oldFixCreated   = 1700000000
	oldFixExpires   = 1700000030
	oldFixAgentKID  = "agent-demo.v1"
	oldFixBrokerKID = "broker.relay.a"
	oldFixAgentPub  = "25lf4lFp0UHKubu6krqgH58uHs599MsqwFGQ83_MH50"
	oldFixBrokerPub = "IVL40Zt5HSRFMkLhXy6rbLfP-ntqXtMAl5YOBpiB2xI"
	oldFixDigest    = "sha-256=:6pDQ/6bKcYsfyGVp/+ue7bCaUmjzXcSYMm6DgMoXkt8=:"
	oldFixBody      = `{"query":"foo"}`
	oldFixTarget    = "https://exchange.example/ramp.v1.ExchangeService/DiscoverResources"
	oldFixSigInput  = `sig1=("@method" "@target-uri" "content-digest" "authorization");keyid="agent-demo.v1";alg="ed25519";created=1700000000;expires=1700000030, sig2=("@method" "@target-uri" "content-digest" "authorization" "signature";key="sig1");keyid="broker.relay.a";alg="ed25519";created=1700000000;expires=1700000030`
	oldFixSignature = `sig1=:Yb0QdsBaECQeCqOTNW+8fL5ne4T32SjLpdpYQjtl4JpGhpWvSDNyo1wQ0FJuBCFdDdpiyvOBpJhSrZjDfwRCCw==:, sig2=:RZ06CZyhourIX4F+RSxgpjcchelYz2Yw8+NrYK2NQYlWNWVL4FaLf79LH2ucm7Xl3k4waRFg6ILNXsL5/6T5BA==:`
)

// TestWBASplit_RejectsPreSignatureAgentSignature pins the deliberate wire break
// the WBA split introduces: signature-agent is now a REQUIRED covered component,
// so a pre-WBA signature (whose covered set is @method @target-uri
// content-digest authorization, with NO signature-agent) is rejected. RAMP has
// zero deployed users, so this is a clean flag-day break, not a rollout regression
// — the frozen fixture below is the exact bytes the old hand-rolled signer put on
// the wire, and the verifier MUST refuse it with ErrMissingRequiredComponent.
func TestWBASplit_RejectsPreSignatureAgentSignature(t *testing.T) {
	agentPub := mustB64Key(t, oldFixAgentPub)
	brokerPub := mustB64Key(t, oldFixBrokerPub)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, oldFixTarget, bytes.NewReader([]byte(oldFixBody)))
	if err != nil {
		t.Fatal(err)
	}
	req.Host = "exchange.example"
	req.Header.Set("Authorization", "Bearer test-jwt")
	req.Header.Set("Content-Digest", oldFixDigest)
	req.Header.Set("Signature-Input", oldFixSigInput)
	req.Header.Set("Signature", oldFixSignature)

	resolver := helpers.NewStaticKeyResolver(map[string]ed25519.PublicKey{
		oldFixAgentKID:  agentPub,
		oldFixBrokerKID: brokerPub,
	})
	// Clock inside the fixture's [created, expires] window so the ONLY reason to
	// reject is the missing signature-agent covered component.
	verifyAt := clock.NewDeterministic(time.Unix(oldFixCreated+10, 0))

	_, err = VerifyMultisigRequest(req, resolver, VerifyRequestOptions{Clk: verifyAt})
	if !errors.Is(err, ErrMissingRequiredComponent) {
		t.Fatalf("want ErrMissingRequiredComponent for a pre-WBA signature, got %v", err)
	}
}

func mustB64Key(t *testing.T, b64 string) ed25519.PublicKey {
	t.Helper()
	raw, err := base64.RawURLEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("decode key %q: %v", b64, err)
	}
	return ed25519.PublicKey(raw)
}
