package runhttp

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"time"
)

// healthProbeTimeout bounds one healthcheck probe end to end; compose gives
// the probe command a 3s budget, so the HTTP call must give up first.
const healthProbeTimeout = 2 * time.Second

// MaybeHealthcheck turns the service binary into its own liveness probe: when
// the process was invoked as `<binary> healthcheck`, it GETs the local
// /healthz and exits 0 (200) or 1 (anything else), never returning to the
// caller. Any other invocation is a no-op. The distroless runtime images ship
// no shell, curl, or wget, so a compose healthcheck can only exec the service
// binary itself. addrEnv/defaultAddr mirror the listen-address resolution of
// the serving path so the probe always targets the port the service bound.
func MaybeHealthcheck(addrEnv, defaultAddr string) {
	if len(os.Args) < 2 || os.Args[1] != "healthcheck" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), healthProbeTimeout)
	err := ProbeHealthz(ctx, EnvOr(addrEnv, defaultAddr))
	cancel() // explicit (not deferred): os.Exit below never runs defers
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		os.Exit(1)
	}
	os.Exit(0)
}

// ProbeHealthz GETs http://<addr>/healthz and returns nil iff it answers 200.
// addr is a listen address (":8081", "0.0.0.0:8081"); wildcard or empty hosts
// are probed via loopback since the probe runs inside the same container.
func ProbeHealthz(ctx context.Context, addr string) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("healthz addr %q: %w", addr, err)
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "127.0.0.1"
	}
	url := "http://" + net.JoinHostPort(host, port) + "/healthz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, http.NoBody)
	if err != nil {
		return fmt.Errorf("healthz request: %w", err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return fmt.Errorf("healthz probe: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("healthz %s: status %d", url, resp.StatusCode)
	}
	return nil
}
