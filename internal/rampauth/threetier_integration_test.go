//go:build integration

package rampauth_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	connect "connectrpc.com/connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampauth"
)

// carriageHandler is a minimal HTTP surface that simulates the
// Exchange's service-boundary use of rampauth.CanonicalBiscuit: it
// reads the header via ReadEntitlementBiscuit, reads synthetic envelope
// and sub-message biscuit fields out of the JSON body, and applies the
// three-tier precedence rule. On conflict it returns 400 with a
// connect-shaped error body so callers can assert the wire code.
func carriageHandler(w http.ResponseWriter, r *http.Request) {
	header, err := rampauth.ReadEntitlementBiscuit(r)
	if err != nil {
		writeConnectErr(w, http.StatusBadRequest, connect.CodeInvalidArgument, err)
		return
	}
	body, _ := io.ReadAll(r.Body)
	var payload struct {
		EnvelopeBiscuit   string `json:"envelope_biscuit"`
		SubMessageBiscuit string `json:"submessage_biscuit"`
	}
	_ = json.Unmarshal(body, &payload)
	envelope, err := decodeOptionalB64(payload.EnvelopeBiscuit)
	if err != nil {
		writeConnectErr(w, http.StatusBadRequest, connect.CodeInvalidArgument, err)
		return
	}
	submessage, err := decodeOptionalB64(payload.SubMessageBiscuit)
	if err != nil {
		writeConnectErr(w, http.StatusBadRequest, connect.CodeInvalidArgument, err)
		return
	}
	ctx := r.Context()
	if header != nil {
		ctx = rampauth.WithEntitlementBiscuit(ctx, header)
	}
	canonical, err := rampauth.CanonicalBiscuit(ctx, envelope, submessage)
	if err != nil {
		writeConnectErr(w, http.StatusBadRequest, connect.CodeInvalidArgument, err)
		return
	}
	resp, _ := json.Marshal(map[string]string{
		"canonical_b64": base64.RawURLEncoding.EncodeToString(canonical),
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(resp)
}

func decodeOptionalB64(s string) ([]byte, error) {
	if s == "" {
		return nil, nil
	}
	return base64.RawURLEncoding.DecodeString(s)
}

func writeConnectErr(w http.ResponseWriter, status int, code connect.Code, err error) {
	body, _ := json.Marshal(map[string]string{
		"code":    code.String(),
		"message": err.Error(),
	})
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// TestIntegration_ThreeTier_HeaderVsEnvelopeConflict drives a full HTTP
// round trip with both header and envelope populated. Under three-tier
// rules this MUST be rejected — the sender should pick one tier.
func TestIntegration_ThreeTier_HeaderVsEnvelopeConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(carriageHandler))
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]string{
		"envelope_biscuit": base64.RawURLEncoding.EncodeToString([]byte("envelope-bytes")),
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(rampauth.EntitlementHeader, base64.RawURLEncoding.EncodeToString([]byte("header-bytes")))

	expectConflict(t, req)
}

// TestIntegration_ThreeTier_HeaderVsSubMessageConflict — same but the
// second carrier is a sub-message field.
func TestIntegration_ThreeTier_HeaderVsSubMessageConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(carriageHandler))
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]string{
		"submessage_biscuit": base64.RawURLEncoding.EncodeToString([]byte("sub-bytes")),
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(rampauth.EntitlementHeader, base64.RawURLEncoding.EncodeToString([]byte("header-bytes")))

	expectConflict(t, req)
}

// TestIntegration_ThreeTier_EnvelopeVsSubMessageConflict — both body
// fields populated.
func TestIntegration_ThreeTier_EnvelopeVsSubMessageConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(carriageHandler))
	t.Cleanup(srv.Close)

	body, _ := json.Marshal(map[string]string{
		"envelope_biscuit":   base64.RawURLEncoding.EncodeToString([]byte("envelope-bytes")),
		"submessage_biscuit": base64.RawURLEncoding.EncodeToString([]byte("sub-bytes")),
	})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	expectConflict(t, req)
}

// TestIntegration_ThreeTier_IdenticalBytesStillConflict — three-tier is
// strict, byte-equal duplicates across carriers are still a sender bug.
func TestIntegration_ThreeTier_IdenticalBytesStillConflict(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(carriageHandler))
	t.Cleanup(srv.Close)

	same := []byte("same-bytes-in-two-tiers")
	encoded := base64.RawURLEncoding.EncodeToString(same)
	body, _ := json.Marshal(map[string]string{"envelope_biscuit": encoded})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(rampauth.EntitlementHeader, encoded)

	expectConflict(t, req)
}

// TestIntegration_ThreeTier_Tier1HeaderAccepted — happy path Tier 1.
func TestIntegration_ThreeTier_Tier1HeaderAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(carriageHandler))
	t.Cleanup(srv.Close)

	encoded := base64.RawURLEncoding.EncodeToString([]byte("tier-1"))
	body, _ := json.Marshal(map[string]string{})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(rampauth.EntitlementHeader, encoded)

	expectCanonical(t, req, encoded)
}

// TestIntegration_ThreeTier_Tier2EnvelopeAccepted — happy path Tier 2
// (RAMPRequest.entitlement_biscuit alone).
func TestIntegration_ThreeTier_Tier2EnvelopeAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(carriageHandler))
	t.Cleanup(srv.Close)

	encoded := base64.RawURLEncoding.EncodeToString([]byte("tier-2"))
	body, _ := json.Marshal(map[string]string{"envelope_biscuit": encoded})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	expectCanonical(t, req, encoded)
}

// TestIntegration_ThreeTier_Tier3SubMessageAccepted — happy path Tier 3
// (sub-message standalone).
func TestIntegration_ThreeTier_Tier3SubMessageAccepted(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(carriageHandler))
	t.Cleanup(srv.Close)

	encoded := base64.RawURLEncoding.EncodeToString([]byte("tier-3"))
	body, _ := json.Marshal(map[string]string{"submessage_biscuit": encoded})
	req, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, srv.URL, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")

	expectCanonical(t, req, encoded)
}

// TestIntegration_ThreeTier_Tier3SubMessageUnit — unit-level sanity
// requested by the team lead: parse a request with ONLY the
// sub-message slot populated and verify the extraction helper returns
// those bytes. No HTTP round-trip needed for this one.
func TestIntegration_ThreeTier_Tier3SubMessageUnit(t *testing.T) {
	subBytes := []byte("tier-3-sub-only")
	out, err := rampauth.CanonicalBiscuit(context.Background(), nil, subBytes)
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if string(out) != string(subBytes) {
		t.Fatalf("want %q got %q", subBytes, out)
	}
}

// -----------------------------------------------------------------------------
// Helpers.

func expectConflict(t *testing.T, req *http.Request) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400", resp.StatusCode)
	}
	var decoded struct {
		Code, Message string
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.Code != connect.CodeInvalidArgument.String() {
		t.Fatalf("code = %q, want invalid_argument", decoded.Code)
	}
	if !containsIgnoreCase(decoded.Message, "conflicting biscuit carriers") {
		t.Fatalf("message = %q, want 'conflicting biscuit carriers' substring", decoded.Message)
	}
}

func expectCanonical(t *testing.T, req *http.Request, wantEncoded string) {
	t.Helper()
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	var decoded struct {
		CanonicalB64 string `json:"canonical_b64"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if decoded.CanonicalB64 != wantEncoded {
		t.Fatalf("canonical = %q, want %q", decoded.CanonicalB64, wantEncoded)
	}
}

func containsIgnoreCase(haystack, needle string) bool {
	h := []byte(haystack)
	n := []byte(needle)
	if len(n) == 0 {
		return true
	}
	if len(h) < len(n) {
		return false
	}
	for i := 0; i+len(n) <= len(h); i++ {
		match := true
		for j := range n {
			a, b := h[i+j], n[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}
