// Package exa adapts EXA search (https://exa.ai) for Broker discovery.
//
// The DiscoveryClient interface lets handlers depend on a narrow contract;
// tests inject a fake implementation backed by httptest. The real client hits
// https://api.exa.ai/search with a bearer token from EXA_API_KEY.
package exa

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultEndpoint is api.exa.ai/search.
const DefaultEndpoint = "https://api.exa.ai/search"

// Candidate is a result row returned by discovery.
type Candidate struct {
	URL    string
	Domain string
	Title  string
	Score  float64
}

// DiscoveryClient is the narrow interface the Broker depends on.
type DiscoveryClient interface {
	Search(ctx context.Context, query string) ([]Candidate, error)
}

// HTTPDoer is the minimal HTTP contract exa.Client depends on.
type HTTPDoer interface {
	Do(req *http.Request) (*http.Response, error)
}

// Client is the real EXA client.
type Client struct {
	http     HTTPDoer
	apiKey   string
	endpoint string
	limit    int
	timeout  time.Duration
}

// Options configures Client.
type Options struct {
	Endpoint string
	Limit    int
	Timeout  time.Duration
}

// NewClient constructs a live EXA client.
func NewClient(httpClient HTTPDoer, apiKey string, opts Options) (*Client, error) {
	if apiKey == "" {
		return nil, errors.New("exa: EXA_API_KEY is required for live client")
	}
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 10 * time.Second}
	}
	if opts.Endpoint == "" {
		opts.Endpoint = DefaultEndpoint
	}
	if opts.Limit <= 0 {
		opts.Limit = 10
	}
	if opts.Timeout <= 0 {
		opts.Timeout = 10 * time.Second
	}
	return &Client{
		http:     httpClient,
		apiKey:   apiKey,
		endpoint: opts.Endpoint,
		limit:    opts.Limit,
		timeout:  opts.Timeout,
	}, nil
}

// Search sends a query to EXA and maps the response to Candidate slices.
func (c *Client) Search(ctx context.Context, query string) ([]Candidate, error) {
	payload := map[string]any{
		"query":      query,
		"numResults": c.limit,
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("exa: marshal request: %w", err)
	}
	reqCtx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("exa: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("exa: transport: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("exa: read body: %w", err)
	}
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("exa: status %d: %s", resp.StatusCode, string(raw))
	}
	var parsed struct {
		Results []struct {
			URL   string  `json:"url"`
			Title string  `json:"title"`
			Score float64 `json:"score"`
		} `json:"results"`
	}
	if decodeErr := json.Unmarshal(raw, &parsed); decodeErr != nil {
		return nil, fmt.Errorf("exa: decode response: %w", decodeErr)
	}
	out := make([]Candidate, 0, len(parsed.Results))
	for _, r := range parsed.Results {
		domain, derr := DomainOf(r.URL)
		if derr != nil {
			continue
		}
		out = append(out, Candidate{
			URL:    r.URL,
			Domain: domain,
			Title:  r.Title,
			Score:  r.Score,
		})
	}
	return out, nil
}

// DomainOf extracts the host of a URL, lowercased and stripped of "www.".
func DomainOf(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return "", err
	}
	host := strings.ToLower(u.Host)
	host = strings.TrimPrefix(host, "www.")
	if host == "" {
		return "", errors.New("exa: empty host")
	}
	return host, nil
}

// StaticClient is a DiscoveryClient that returns pre-configured candidates.
// Tests and demos can use this to avoid hitting the EXA API.
type StaticClient struct {
	Candidates []Candidate
}

// Search returns the configured candidates for any query.
func (s *StaticClient) Search(_ context.Context, _ string) ([]Candidate, error) {
	out := make([]Candidate, len(s.Candidates))
	copy(out, s.Candidates)
	return out, nil
}
