package registry

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// DefaultInterval is the polling cadence for marketplace health.
const DefaultInterval = 30 * time.Second

// Refresher periodically probes each marketplace's /healthz and persists the
// latest healthy bool back to broker.marketplaces.
type Refresher struct {
	repo     repo.MarketplaceRepo
	http     *http.Client
	logger   *slog.Logger
	interval time.Duration
	timeout  time.Duration
}

// NewRefresher constructs a Refresher. Pass nil for httpClient to use a default.
func NewRefresher(
	r repo.MarketplaceRepo, httpClient *http.Client,
	logger *slog.Logger, interval time.Duration,
) *Refresher {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 3 * time.Second}
	}
	if interval <= 0 {
		interval = DefaultInterval
	}
	return &Refresher{repo: r, http: httpClient, logger: logger, interval: interval, timeout: 3 * time.Second}
}

// Run blocks until ctx is cancelled, polling every interval.
func (r *Refresher) Run(ctx context.Context) {
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()
	r.tick(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.tick(ctx)
		}
	}
}

func (r *Refresher) tick(ctx context.Context) {
	entries, err := r.repo.List(ctx)
	if err != nil {
		r.logger.WarnContext(ctx, "registry: list failed", "err", err)
		return
	}
	for _, m := range entries {
		healthy := r.ping(ctx, m.Endpoint)
		if m.Healthy == healthy {
			continue
		}
		if setErr := r.repo.SetHealth(ctx, m.ID, healthy); setErr != nil {
			r.logger.WarnContext(ctx, "registry: set health failed",
				"marketplace_id", m.ID, "err", setErr)
		}
	}
}

func (r *Refresher) ping(ctx context.Context, endpoint string) bool {
	url := strings.TrimRight(endpoint, "/") + "/healthz"
	reqCtx, cancel := context.WithTimeout(ctx, r.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	resp, err := r.http.Do(req)
	if err != nil {
		return false
	}
	defer func() { _ = resp.Body.Close() }()
	return resp.StatusCode == http.StatusOK
}
