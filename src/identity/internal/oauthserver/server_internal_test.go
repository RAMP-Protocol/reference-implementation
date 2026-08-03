package oauthserver

import (
	"errors"
	"fmt"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/keystore"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/oauth"
)

// storeUnavailable must be a TOTAL mapping over the outage sentinels the sign-up flow
// composes — the account and oauth stores, the Vault keystore, and the card store —
// including when a service layer %w-wraps them, so a transient backend outage answers
// 503 (retryable), never a bare 500. A Vault outage during /callback provisioning is
// the motivating case: signup wraps keystore.ErrUnavailable, so the classification
// must survive the wrap. This guards the mapping on the always-run unit tier, since a
// real Vault outage cannot be staged through the integration fixture.
func TestStoreUnavailable_RecognizesEveryBackendOutage(t *testing.T) {
	outages := []error{
		oauth.ErrUnavailable,
		account.ErrUnavailable,
		keystore.ErrUnavailable,
		keystore.ErrPermissionDenied,
		directory.ErrCardUnavailable,
	}
	for _, e := range outages {
		if !storeUnavailable(e) {
			t.Errorf("storeUnavailable(%v) = false, want true (bare sentinel)", e)
		}
		// signup and the repos %w-wrap these before they reach a handler.
		if !storeUnavailable(fmt.Errorf("signup: create key: %w", e)) {
			t.Errorf("storeUnavailable(wrapped %v) = false, want true", e)
		}
	}

	// A non-outage error must NOT be classified as a transient outage — that would
	// turn a real 500 (or a not-found) into a misleading, retry-inviting 503.
	if storeUnavailable(errors.New("some other failure")) {
		t.Error("storeUnavailable classified a non-outage error as an outage")
	}
	if storeUnavailable(account.ErrNotFound) {
		t.Error("storeUnavailable classified ErrNotFound as an outage")
	}
}
