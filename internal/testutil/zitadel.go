//go:build integration && zitadel

package testutil

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	mobynet "github.com/moby/moby/api/types/network"
	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/network"
	"github.com/testcontainers/testcontainers-go/wait"
)

// dumpZitadelLogs best-effort streams a failed container's logs to stderr.
// Diagnostic wiring: a Zitadel that fails its port-wait is otherwise opaque in
// CI, and its logs are readable over the Docker API even when the mapped port
// never became reachable (as under GitLab dind) — so the trace shows whether
// Zitadel actually booted and listened, or crashed on startup.
func dumpZitadelLogs(ctx context.Context, c testcontainers.Container) {
	if c == nil {
		return
	}
	rc, err := c.Logs(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "zitadel: could not read container logs: %v\n", err)
		return
	}
	defer func() { _ = rc.Close() }()
	fmt.Fprintln(os.Stderr, "=== zitadel container logs (startup failure) ===")
	_, _ = io.Copy(os.Stderr, rc)
	fmt.Fprintln(os.Stderr, "\n=== end zitadel container logs ===")
}

const (
	zitadelImage     = "ghcr.io/zitadel/zitadel:v3.4.9"
	zitadelPGImage   = "postgres:17-alpine"
	zitadelMasterkey = "MasterkeyNeedsToHave32Characters"
	// zitadelHostPort is a FIXED host port. Zitadel derives its issuer, JWKS URL,
	// and authorize/token endpoints from ExternalDomain:ExternalPort baked at init,
	// not from the request Host — so go-oidc discovery only succeeds if the client
	// reaches Zitadel at exactly that address. A testcontainers ephemeral port would
	// break discovery, verification, and every endpoint URL in the doc. The cost is
	// that this container cannot overlap anything else on the port; StartSharedZitadel
	// surfaces a bind failure as a startup error the caller can skip on.
	zitadelHostPort = "8080"
	// zitadelPATPath is under /app (where the binary lives), NOT /tmp: the minimal
	// Zitadel image has no /tmp, so init-writing the PAT there fails with "no such
	// file or directory". /app exists, is root-writable, and — unlike a tmpfs mount
	// — is readable by CopyFileFromContainer (docker cp cannot read tmpfs).
	zitadelPATPath = "/app/zadmin.pat"
)

// zitadelInitSteps is the FirstInstance provisioning Zitadel runs under
// `start-from-init`: it creates the instance, the `ramp` org, an admin, and the
// `ramp-bootstrap` machine user whose PAT (written to zitadelPATPath) the Go
// bootstrap then authenticates with. Mirrors the retired deploy/zitadel/init-steps.yaml,
// but writes the PAT under /app (see zitadelPATPath) rather than a mounted
// /bootstrap volume the test harness does not create.
const zitadelInitSteps = `FirstInstance:
  InstanceName: "ramp-poc"
  MachineKeyPath: /app/zadmin.key
  PatPath: /app/zadmin.pat
  Org:
    Name: "ramp"
    Human:
      UserName: "zadmin"
      FirstName: "Z"
      LastName: "Admin"
      Email:
        Address: "zadmin@ramp.localhost"
        Verified: true
      Password: "ZAdmin123!"
      PasswordChangeRequired: false
    Machine:
      Machine:
        Username: "ramp-bootstrap"
        Name: "RAMP bootstrap service account"
      MachineKey:
        ExpirationDate: "2099-01-01T00:00:00Z"
        Type: 1
      Pat:
        ExpirationDate: "2099-01-01T00:00:00Z"
`

// SharedZitadel is one real Zitadel v3 instance (plus its own Postgres) brought up
// once per package for the `zitadel` test tier. It carries the coordinates the
// oidcup client and the headless-login helper need. There is no per-test reset:
// each test resets the identity service's own Postgres + Vault and drives a fresh
// login, so the Zitadel instance is read-mostly shared config, not per-test state.
type SharedZitadel struct {
	Issuer       string
	ClientID     string
	ClientSecret string
}

// StartSharedZitadel brings up Zitadel v3.4.9 (pinned — v4.x has an open
// migration-03 boot crash) plus its dedicated Postgres on a private network,
// waits for first-instance init to write the admin PAT, then bootstraps the
// `ramp-mcp` OIDC client and the `alice@acme.local` login user. Returns a handle
// plus a cleanup func for the caller (TestMain) to defer. Sibling of
// StartSharedVault, but heavier: expect ~30-45s startup.
func StartSharedZitadel(ctx context.Context, logger *slog.Logger) (*SharedZitadel, func(), error) {
	net, err := network.New(ctx)
	if err != nil {
		return nil, nil, fmt.Errorf("create zitadel network: %w", err)
	}
	var cleanups []func()
	cleanup := func() {
		for i := len(cleanups) - 1; i >= 0; i-- {
			cleanups[i]()
		}
	}
	cleanups = append(cleanups, func() {
		if rmErr := net.Remove(context.Background()); rmErr != nil {
			logger.Warn("remove zitadel network", "err", rmErr)
		}
	})

	pgC, err := startZitadelPostgres(ctx, net.Name)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	cleanups = append(cleanups, terminateFn(logger, "zitadel postgres", pgC))

	// The host the TEST PROCESS reaches published ports at — "localhost" against a
	// local daemon, but "docker" under GitLab dind, where the daemon runs in the
	// `docker:dind` service and the job container reaches it by that hostname.
	// Zitadel bakes ExternalDomain into its issuer/JWKS/endpoint URLs at init, and
	// the oidcup client + headless login must reach it at exactly that host — so we
	// resolve it from the daemon (via the already-started container's provider) and
	// thread it through ExternalDomain, the issuer, and the bootstrap Host header.
	host, err := pgC.Host(ctx)
	if err != nil {
		cleanup()
		return nil, nil, fmt.Errorf("resolve docker daemon host: %w", err)
	}

	ziC, err := startZitadelContainer(ctx, net.Name, host)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	cleanups = append(cleanups, terminateFn(logger, "zitadel", ziC))

	pat, err := waitForPAT(ctx, ziC)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	issuer := "http://" + host + ":" + zitadelHostPort
	creds, err := bootstrapZitadel(ctx, issuer, host, pat)
	if err != nil {
		cleanup()
		return nil, nil, err
	}
	return &SharedZitadel{Issuer: issuer, ClientID: creds.clientID, ClientSecret: creds.clientSecret}, cleanup, nil
}

func startZitadelPostgres(ctx context.Context, netName string) (testcontainers.Container, error) {
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: zitadelPGImage,
			Env: map[string]string{
				"POSTGRES_USER":     "zitadel",
				"POSTGRES_PASSWORD": "zitadel",
				"POSTGRES_DB":       "zitadel",
			},
			ExposedPorts:   []string{"5432/tcp"},
			Networks:       []string{netName},
			NetworkAliases: map[string][]string{netName: {"zitadel-db"}},
			WaitingFor:     wait.ForListeningPort("5432/tcp").WithStartupTimeout(60 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		return nil, fmt.Errorf("start zitadel postgres: %w", err)
	}
	return c, nil
}

func startZitadelContainer(ctx context.Context, netName, host string) (testcontainers.Container, error) {
	c, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
		ContainerRequest: testcontainers.ContainerRequest{
			Image: zitadelImage,
			Cmd: []string{
				"start-from-init", "--masterkey", zitadelMasterkey,
				"--tlsMode", "disabled", "--steps", "/etc/zitadel/init-steps.yaml",
			},
			Env:          zitadelEnv(host),
			ExposedPorts: []string{zitadelHostPort + "/tcp"},
			Networks:     []string{netName},
			Files: []testcontainers.ContainerFile{{
				Reader:            strings.NewReader(zitadelInitSteps),
				ContainerFilePath: "/etc/zitadel/init-steps.yaml",
				FileMode:          0o644,
			}},
			ConfigModifier: func(c *container.Config) { c.User = "0" },
			HostConfigModifier: func(hc *container.HostConfig) {
				// Bind 0.0.0.0, not 127.0.0.1: under dind the job container reaches
				// this published port at the daemon host (`docker:8080`), which a
				// loopback-only binding refuses. A fixed host port (not ephemeral)
				// is still required because ExternalPort=8080 is baked at init.
				hc.PortBindings = mobynet.PortMap{
					mobynet.MustParsePort(zitadelHostPort + "/tcp"): []mobynet.PortBinding{
						{HostIP: netip.MustParseAddr("0.0.0.0"), HostPort: zitadelHostPort},
					},
				}
			},
			WaitingFor: wait.ForListeningPort(zitadelHostPort + "/tcp").
				WithStartupTimeout(180 * time.Second),
		},
		Started: true,
	})
	if err != nil {
		// c may be non-nil on a wait failure — dump its logs before wrapping.
		dumpZitadelLogs(ctx, c)
		return nil, fmt.Errorf("start zitadel: %w", err)
	}
	return c, nil
}

// zitadelEnv mirrors the retired docker-compose.e2e.yml zitadel service: a
// non-TLS instance on <host>:8080 backed by the `zitadel-db` Postgres reached
// over the private network. host is the daemon host the test process resolves to
// (localhost locally, docker under dind); it becomes ExternalDomain, so Zitadel's
// issuer and endpoint URLs are the ones the client can actually reach.
func zitadelEnv(host string) map[string]string {
	return map[string]string{
		"ZITADEL_EXTERNALDOMAIN":                   host,
		"ZITADEL_EXTERNALPORT":                     zitadelHostPort,
		"ZITADEL_EXTERNALSECURE":                   "false",
		"ZITADEL_PORT":                             zitadelHostPort,
		"ZITADEL_TLS_ENABLED":                      "false",
		"ZITADEL_DATABASE_POSTGRES_HOST":           "zitadel-db",
		"ZITADEL_DATABASE_POSTGRES_PORT":           "5432",
		"ZITADEL_DATABASE_POSTGRES_DATABASE":       "zitadel",
		"ZITADEL_DATABASE_POSTGRES_USER_USERNAME":  "zitadel",
		"ZITADEL_DATABASE_POSTGRES_USER_PASSWORD":  "zitadel",
		"ZITADEL_DATABASE_POSTGRES_USER_SSL_MODE":  "disable",
		"ZITADEL_DATABASE_POSTGRES_ADMIN_USERNAME": "zitadel",
		"ZITADEL_DATABASE_POSTGRES_ADMIN_PASSWORD": "zitadel",
		"ZITADEL_DATABASE_POSTGRES_ADMIN_SSL_MODE": "disable",
	}
}

// waitForPAT polls the admin PAT out of the container. Zitadel may report its
// port listening a beat before FirstInstance finishes writing the PAT, so this
// retries the copy until the file is non-empty rather than reading once.
func waitForPAT(ctx context.Context, c testcontainers.Container) (string, error) {
	deadline := time.Now().Add(120 * time.Second)
	for {
		if pat := tryReadPAT(ctx, c); pat != "" {
			return pat, nil
		}
		if time.Now().After(deadline) {
			return "", fmt.Errorf("zitadel: admin PAT %s not written within timeout", zitadelPATPath)
		}
		time.Sleep(time.Second)
	}
}

func tryReadPAT(ctx context.Context, c testcontainers.Container) string {
	r, err := c.CopyFileFromContainer(ctx, zitadelPATPath)
	if err != nil {
		return ""
	}
	defer func() { _ = r.Close() }()
	b, err := io.ReadAll(r)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

func terminateFn(logger *slog.Logger, name string, c testcontainers.Container) func() {
	return func() {
		if err := c.Terminate(context.Background()); err != nil {
			logger.Warn("terminate "+name, "err", err)
		}
	}
}
