//go:build integration

package testutil

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

const (
	tigerbeetleImage    = "ghcr.io/tigerbeetle/tigerbeetle:0.17.8"
	tigerbeetleDataFile = "/data/0_0.tigerbeetle"
)

// tigerbeetleFormatStart formats a single-replica data file then starts the
// replica, in one shell entrypoint. The pinned image ships a shell and puts the
// binary at /tigerbeetle; `--development` relaxes Direct IO (Docker overlay/bind
// and macOS volumes) and shrinks caches for CI; `exec` makes the replica the
// container's main process so testcontainers' stop signal reaches it.
const tigerbeetleFormatStart = "mkdir -p /data && " +
	"/tigerbeetle format --cluster=0 --replica=0 --replica-count=1 --development " + tigerbeetleDataFile + " && " +
	"exec /tigerbeetle start --addresses=0.0.0.0:3000 --cache-grid=256MiB --development " + tigerbeetleDataFile

// SharedTigerBeetle is one single-replica TigerBeetle cluster brought up once per
// package. TigerBeetle is append-only with no snapshot/restore, so tests isolate
// by salting business ids (Salt) rather than resetting the container — the
// TigerBeetle analogue of SharedPostgres.Reset / SharedRedis FLUSHDB.
type SharedTigerBeetle struct {
	// Address is the host:port the client dials; stable for the container's life.
	Address string
	counter atomic.Uint64
}

// Salt returns a token unique to each call, so every test — and every table case
// within a test — derives disjoint account/transfer ids. Tests prepend it to
// business ids; production hashing stays unsalted.
func (s *SharedTigerBeetle) Salt(tb testing.TB) string {
	tb.Helper()
	return fmt.Sprintf("%s#%d", tb.Name(), s.counter.Add(1))
}

// StartSharedTigerBeetle brings up one TigerBeetle container and returns a handle
// plus a cleanup func for the caller (TestMain) to defer. It does NOT import the
// tigerbeetle-go client: readiness is the "listening on" log line, so this shared
// test-infra layer stays free of the CGO client (the exchange package owns the
// only client). The seccomp/IPC_LOCK host config is mandatory on Docker >= 25
// (io_uring) and macOS (memlock). Sibling of StartSharedRedis.
func StartSharedTigerBeetle(ctx context.Context, logger *slog.Logger) (*SharedTigerBeetle, func(), error) {
	req := testcontainers.ContainerRequest{
		Image:        tigerbeetleImage,
		Entrypoint:   []string{"sh", "-c"},
		Cmd:          []string{tigerbeetleFormatStart},
		ExposedPorts: []string{"3000/tcp"},
		WaitingFor:   wait.ForLog("listening on").WithStartupTimeout(60 * time.Second),
		HostConfigModifier: func(hc *container.HostConfig) {
			hc.SecurityOpt = []string{"seccomp=unconfined"}
			hc.CapAdd = []string{"IPC_LOCK"}
		},
	}
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: req,
		Started:          true,
	})
	if err != nil {
		return nil, nil, fmt.Errorf("start tigerbeetle: %w", err)
	}
	addr, err := tigerbeetleAddress(ctx, c)
	if err != nil {
		_ = c.Terminate(context.Background()) // best-effort; Ryuk backstops
		return nil, nil, err
	}
	cleanup := func() {
		if termErr := c.Terminate(context.Background()); termErr != nil {
			logger.Warn("terminate tigerbeetle", "err", termErr)
		}
	}
	return &SharedTigerBeetle{Address: addr}, cleanup, nil
}

// tigerbeetleAddress resolves the mapped host:port for the container's port 3000.
// TigerBeetle validates client addresses as IP:port and rejects hostnames, so any
// hostname testcontainers reports is resolved to an IP literal first — "localhost"
// under a local daemon, the daemon's hostname under a remote DOCKER_HOST (GitLab
// dind reports the service alias "docker").
func tigerbeetleAddress(ctx context.Context, c testcontainers.Container) (string, error) {
	host, err := c.Host(ctx)
	if err != nil {
		return "", fmt.Errorf("tigerbeetle host: %w", err)
	}
	ip, err := resolveIPv4(ctx, host)
	if err != nil {
		return "", err
	}
	port, err := c.MappedPort(ctx, "3000/tcp")
	if err != nil {
		return "", fmt.Errorf("tigerbeetle port: %w", err)
	}
	return net.JoinHostPort(ip, port.Port()), nil
}

// resolveIPv4 returns host unchanged when it is already an IP literal, otherwise
// resolves it and returns the first IPv4 address. IPv4 is preferred because the
// TigerBeetle address parser takes bare ip:port pairs, so an IPv6 answer such as
// localhost's ::1 would need bracket quoting the client does not accept.
func resolveIPv4(ctx context.Context, host string) (string, error) {
	if net.ParseIP(host) != nil {
		return host, nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return "", fmt.Errorf("tigerbeetle resolve host %q: %w", host, err)
	}
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			return v4.String(), nil
		}
	}
	return "", fmt.Errorf("tigerbeetle resolve host %q: no IPv4 address", host)
}
