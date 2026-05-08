package exa_test

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/exa"
)

func TestClient_Search_ParsesResults(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer secret" {
			t.Errorf("Authorization = %q", got)
		}
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), `"query":"RAMP"`) {
			t.Errorf("unexpected body: %s", body)
		}
		_, _ = io.WriteString(w, `{"results":[{"url":"https://Acme.example/article","title":"RAMP tutorial","score":0.98}]}`)
	}))
	defer srv.Close()

	c, err := exa.NewClient(http.DefaultClient, "secret", exa.Options{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	got, err := c.Search(context.Background(), "RAMP")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d candidates, want 1", len(got))
	}
	if got[0].Domain != "acme.example" {
		t.Errorf("domain = %q", got[0].Domain)
	}
	if got[0].Title != "RAMP tutorial" {
		t.Errorf("title = %q", got[0].Title)
	}
}

func TestClient_Search_HTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, `{"error":"bad token"}`)
	}))
	defer srv.Close()

	c, err := exa.NewClient(http.DefaultClient, "secret", exa.Options{Endpoint: srv.URL})
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	if _, err := c.Search(context.Background(), "q"); err == nil {
		t.Fatal("expected error")
	}
}

func TestNewClient_RequiresAPIKey(t *testing.T) {
	if _, err := exa.NewClient(http.DefaultClient, "", exa.Options{}); err == nil {
		t.Fatal("expected error for empty API key")
	}
}

func TestDomainOf_StripsWWW(t *testing.T) {
	got, err := exa.DomainOf("https://www.Example.com/a/b")
	if err != nil {
		t.Fatalf("DomainOf: %v", err)
	}
	if got != "example.com" {
		t.Errorf("got %q", got)
	}
}

func TestStaticClient_Search(t *testing.T) {
	s := &exa.StaticClient{Candidates: []exa.Candidate{{Domain: "a.example"}}}
	got, err := s.Search(context.Background(), "any")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(got) != 1 || got[0].Domain != "a.example" {
		t.Errorf("got %+v", got)
	}
}
