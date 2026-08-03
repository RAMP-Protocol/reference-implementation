package runhttp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

// observeRequest serves one real HTTP request through the given middleware
// chain and returns the request as the innermost handler saw it. Requests go
// over a live httptest listener so the observed shape (empty URL.Scheme/Host,
// populated Host) is exactly what a production server hands the middleware.
func observeRequest(t *testing.T, wrap func(http.Handler) http.Handler, decorate func(*http.Request)) *http.Request {
	t.Helper()
	var seen *http.Request
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r
		w.WriteHeader(http.StatusNoContent)
	})
	srv := httptest.NewServer(wrap(inner))
	defer srv.Close()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL+"/probe", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	decorate(req)
	resp, err := srv.Client().Do(req)
	if err != nil {
		t.Fatalf("do request: %v", err)
	}
	_ = resp.Body.Close()
	if seen == nil {
		t.Fatal("inner handler never ran")
	}
	return seen
}

func TestTrustProxyHeaders_RewritesSchemeFromForwardedProto(t *testing.T) {
	seen := observeRequest(t, TrustProxyHeaders, func(req *http.Request) {
		req.Header.Set("X-Forwarded-Proto", "https")
	})
	if seen.URL.Scheme != "https" {
		t.Fatalf("URL.Scheme = %q, want %q", seen.URL.Scheme, "https")
	}
	// Host untouched: the middleware is scheme-only by design.
	if seen.URL.Host != "" {
		t.Fatalf("URL.Host = %q, want empty (fall back to Host header)", seen.URL.Host)
	}
}

func TestTrustProxyHeaders_ForwardedHostIsNotHonored(t *testing.T) {
	seen := observeRequest(t, TrustProxyHeaders, func(req *http.Request) {
		req.Header.Set("X-Forwarded-Proto", "https")
		req.Header.Set("X-Forwarded-Host", "attacker.example")
	})
	if seen.URL.Host != "" {
		t.Fatalf("URL.Host = %q, want empty (X-Forwarded-Host must be ignored)", seen.URL.Host)
	}
	if seen.Host == "attacker.example" {
		t.Fatal("Host rewritten from X-Forwarded-Host; the header must be ignored")
	}
}

func TestTrustProxyHeaders_NoHeadersLeavesRequestUntouched(t *testing.T) {
	seen := observeRequest(t, TrustProxyHeaders, func(*http.Request) {})
	if seen.URL.Scheme != "" {
		t.Fatalf("URL.Scheme = %q, want empty (socket decides)", seen.URL.Scheme)
	}
	if seen.URL.Host != "" {
		t.Fatalf("URL.Host = %q, want empty", seen.URL.Host)
	}
}

func TestTrustProxyHeaders_MultiHopValueTakesFirstToken(t *testing.T) {
	seen := observeRequest(t, TrustProxyHeaders, func(req *http.Request) {
		req.Header.Set("X-Forwarded-Proto", "https, http")
	})
	if seen.URL.Scheme != "https" {
		t.Fatalf("URL.Scheme = %q, want %q (first hop wins)", seen.URL.Scheme, "https")
	}
}

func TestTrustProxyHeaders_NonSchemeValueIgnored(t *testing.T) {
	seen := observeRequest(t, TrustProxyHeaders, func(req *http.Request) {
		req.Header.Set("X-Forwarded-Proto", "gopher://weird")
	})
	if seen.URL.Scheme != "" {
		t.Fatalf("URL.Scheme = %q, want empty (non-http(s) value must be ignored)", seen.URL.Scheme)
	}
}

func TestTrustProxyHeaders_CaseAndWhitespaceNormalized(t *testing.T) {
	seen := observeRequest(t, TrustProxyHeaders, func(req *http.Request) {
		req.Header.Set("X-Forwarded-Proto", " HTTPS ")
	})
	if seen.URL.Scheme != "https" {
		t.Fatalf("URL.Scheme = %q, want %q", seen.URL.Scheme, "https")
	}
}

// serveNormalize drives one crafted request through NormalizeToOriginForm and
// reports the recorded status and whether the inner handler ran. Unlike
// observeRequest it takes a fully-formed *http.Request (a live http.Client always
// emits origin-form, so an absolute-form URL — URL.Scheme/Host populated — can
// only be simulated by constructing the request directly, exactly as net/http's
// server does for an absolute-form line).
func serveNormalize(req *http.Request) (status int, innerRan bool) {
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		innerRan = true
		w.WriteHeader(http.StatusNoContent)
	})
	rec := httptest.NewRecorder()
	NormalizeToOriginForm(inner).ServeHTTP(rec, req)
	return rec.Code, innerRan
}

func TestNormalizeToOriginForm_RejectsAbsoluteFormScheme(t *testing.T) {
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "http://real.example/rpc?q=1", nil)
	// net/http populates these for an absolute-form request line
	// (POST https://attacker.example/rpc HTTP/1.1).
	req.URL.Scheme = "https"
	req.URL.Host = "attacker.example"

	status, innerRan := serveNormalize(req)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (absolute-form rejected)", status)
	}
	if innerRan {
		t.Fatal("inner handler ran; an absolute-form request must be refused before it")
	}
}

func TestNormalizeToOriginForm_RejectsAbsoluteFormHostOnly(t *testing.T) {
	// Host set but scheme empty is still absolute-form (the host-spoof half).
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/rpc", nil)
	req.URL.Host = "attacker.example"

	status, innerRan := serveNormalize(req)
	if status != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (absolute-form host rejected)", status)
	}
	if innerRan {
		t.Fatal("inner handler ran; a host-bearing target must be refused")
	}
}

func TestNormalizeToOriginForm_PassesOriginForm(t *testing.T) {
	// Origin-form (and HTTP/2) leave URL.Scheme/Host empty — the request passes.
	req := httptest.NewRequestWithContext(context.Background(), http.MethodPost, "/rpc?q=1", nil)
	req.URL.Scheme = ""
	req.URL.Host = ""

	status, innerRan := serveNormalize(req)
	if !innerRan {
		t.Fatal("inner handler did not run for a legitimate origin-form request")
	}
	if status != http.StatusNoContent {
		t.Fatalf("status = %d, want 204 (origin-form passed through)", status)
	}
}
