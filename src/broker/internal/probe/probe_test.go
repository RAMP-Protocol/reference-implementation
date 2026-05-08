package probe_test

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/probe"
)

// rewritingClient rewrites an https request targeting domain "X" to hit the
// given httptest base URL, so probe can be exercised over loopback.
type rewritingClient struct {
	base string
}

func (c *rewritingClient) Do(req *http.Request) (*http.Response, error) {
	u, err := url.Parse(c.base + req.URL.Path)
	if err != nil {
		return nil, err
	}
	req.URL = u
	req.Host = u.Host
	return http.DefaultTransport.RoundTrip(req)
}

func TestProbe_PresentManifest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/.well-known/ramp.json" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ver":"0.3","provider":"acme.example","exchanges":[{"domain":"mp.example","endpoint":"https://mp.example/ramp","supported_profiles":["ramp-news-v1"]}]}`)
	}))
	defer srv.Close()

	p := probe.New(&rewritingClient{base: srv.URL}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		probe.Options{Scheme: "http", TTL: time.Minute})

	res, err := p.Probe(context.Background(), "acme.example")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if !res.Present {
		t.Fatal("expected Present = true")
	}
	if got := res.Manifest.Provider; got != "acme.example" {
		t.Errorf("provider = %q, want acme.example", got)
	}
	if len(res.Manifest.Exchanges) != 1 {
		t.Fatalf("marketplaces = %d, want 1", len(res.Manifest.Exchanges))
	}
	if res.Manifest.Exchanges[0].Endpoint != "https://mp.example/ramp" {
		t.Errorf("endpoint = %q", res.Manifest.Exchanges[0].Endpoint)
	}
}

func TestProbe_404ReturnsNotPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	p := probe.New(&rewritingClient{base: srv.URL}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		probe.Options{Scheme: "http", TTL: time.Minute})

	res, err := p.Probe(context.Background(), "unlicensed.example")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Present {
		t.Fatal("expected Present = false for 404")
	}
}

func TestProbe_MalformedReturnsNotPresent(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `not-json`)
	}))
	defer srv.Close()

	p := probe.New(&rewritingClient{base: srv.URL}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		probe.Options{Scheme: "http", TTL: time.Minute})

	res, err := p.Probe(context.Background(), "bad.example")
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if res.Present {
		t.Fatal("expected Present = false for malformed body")
	}
}

func TestProbe_UsesMemCache(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits++
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, `{"ver":"0.3","provider":"cache.example","exchanges":[]}`)
	}))
	defer srv.Close()

	p := probe.New(&rewritingClient{base: srv.URL}, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		probe.Options{Scheme: "http", TTL: time.Minute})

	for range 3 {
		if _, err := p.Probe(context.Background(), "cache.example"); err != nil {
			t.Fatalf("Probe: %v", err)
		}
	}
	if hits != 1 {
		t.Errorf("expected 1 upstream hit, got %d", hits)
	}
}

func TestProbe_EmptyDomain(t *testing.T) {
	p := probe.New(http.DefaultClient, nil,
		slog.New(slog.NewTextHandler(io.Discard, nil)), probe.Options{})
	_, err := p.Probe(context.Background(), "   ")
	if err == nil || !strings.Contains(err.Error(), "invalid") {
		t.Errorf("want ErrInvalidDomain, got %v", err)
	}
}
