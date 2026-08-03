package runhttp

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// healthzServer starts a loopback HTTP server whose /healthz answers with the
// given status, and returns its listen address (host:port).
func healthzServer(t *testing.T, status int) string {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(status)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return strings.TrimPrefix(srv.URL, "http://")
}

// TestProbeHealthz_OK pins the success contract the compose healthcheck rides
// on: a 200 from /healthz probes clean.
func TestProbeHealthz_OK(t *testing.T) {
	t.Parallel()
	addr := healthzServer(t, http.StatusOK)
	if err := ProbeHealthz(context.Background(), addr); err != nil {
		t.Fatalf("ProbeHealthz on healthy server: %v", err)
	}
}

// TestProbeHealthz_NonOKStatus pins the degraded contract: the Exchange and
// Broker /healthz answer 503 when the database ping fails, and the probe must
// report that as unhealthy, not merely "the server answered".
func TestProbeHealthz_NonOKStatus(t *testing.T) {
	t.Parallel()
	addr := healthzServer(t, http.StatusServiceUnavailable)
	err := ProbeHealthz(context.Background(), addr)
	if err == nil {
		t.Fatal("ProbeHealthz on 503 server: want error, got nil")
	}
	if !strings.Contains(err.Error(), "503") {
		t.Fatalf("ProbeHealthz error should name the status, got: %v", err)
	}
}

// TestProbeHealthz_ConnectionRefused pins the down contract: a service that is
// not listening (crash-looping at boot) probes unhealthy.
func TestProbeHealthz_ConnectionRefused(t *testing.T) {
	t.Parallel()
	srv := httptest.NewServer(http.NewServeMux())
	addr := strings.TrimPrefix(srv.URL, "http://")
	srv.Close() // release the port so nothing listens on it
	if err := ProbeHealthz(context.Background(), addr); err == nil {
		t.Fatal("ProbeHealthz against a closed port: want error, got nil")
	}
}

// TestProbeHealthz_WildcardHostFallsBackToLoopback pins the address rewrite:
// the services bind ":8081"-style wildcard addresses, and the probe must
// target loopback for them instead of failing to parse or dialing 0.0.0.0.
func TestProbeHealthz_WildcardHostFallsBackToLoopback(t *testing.T) {
	t.Parallel()
	addr := healthzServer(t, http.StatusOK)
	_, port, ok := strings.Cut(addr, ":")
	if !ok {
		t.Fatalf("unexpected httptest addr %q", addr)
	}
	if err := ProbeHealthz(context.Background(), ":"+port); err != nil {
		t.Fatalf("ProbeHealthz with wildcard host: %v", err)
	}
	if err := ProbeHealthz(context.Background(), "0.0.0.0:"+port); err != nil {
		t.Fatalf("ProbeHealthz with 0.0.0.0 host: %v", err)
	}
}

// TestProbeHealthz_BadAddr pins the misconfiguration contract: an address with
// no port is an error, not a panic or a silent success.
func TestProbeHealthz_BadAddr(t *testing.T) {
	t.Parallel()
	if err := ProbeHealthz(context.Background(), "no-port"); err == nil {
		t.Fatal("ProbeHealthz with portless addr: want error, got nil")
	}
}

// MaybeHealthcheck calls os.Exit, so its dispatch and exit-code mapping — the
// exact contract the compose `healthcheck:` stanzas ride on — can only be
// observed from outside the process. These tests re-execute this test binary
// as a subprocess (the stdlib helper-process pattern): the child runs ONLY
// TestHelperMaybeHealthcheck, which shims os.Args to the requested shape and
// hands control to MaybeHealthcheck; the parent asserts on the child's exit
// code.

const (
	// healthcheckHelperEnv gates the helper: without it the helper test is a
	// skip, so a normal suite run never re-enters MaybeHealthcheck.
	healthcheckHelperEnv = "RUNHTTP_TEST_HEALTHCHECK_HELPER"
	// healthcheckHelperArgEnv carries the os.Args[1] value the helper should
	// present to MaybeHealthcheck ("" = no argument).
	healthcheckHelperArgEnv = "RUNHTTP_TEST_HEALTHCHECK_ARG"
	// healthcheckHelperAddrEnv is the addrEnv name the helper passes to
	// MaybeHealthcheck, so the probe target rides the production EnvOr path.
	healthcheckHelperAddrEnv = "RUNHTTP_TEST_HEALTHCHECK_ADDR"
	// helperReturnedExit marks "MaybeHealthcheck returned instead of exiting"
	// — distinct from 0 and 1, the two codes MaybeHealthcheck itself emits.
	helperReturnedExit = 42
)

// TestHelperMaybeHealthcheck is the subprocess body, not a standalone test.
func TestHelperMaybeHealthcheck(t *testing.T) {
	if os.Getenv(healthcheckHelperEnv) == "" {
		t.Skip("helper process for TestMaybeHealthcheck_*; run via subprocess only")
	}
	os.Args = []string{os.Args[0]}
	if arg := os.Getenv(healthcheckHelperArgEnv); arg != "" {
		os.Args = append(os.Args, arg)
	}
	MaybeHealthcheck(healthcheckHelperAddrEnv, ":0")
	os.Exit(helperReturnedExit)
}

// maybeHealthcheckExitCode re-executes the test binary with os.Args[1]=arg and
// the probe address env set to addr, and returns the child's exit code.
func maybeHealthcheckExitCode(t *testing.T, arg, addr string) int {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), os.Args[0], "-test.run=^TestHelperMaybeHealthcheck$")
	cmd.Env = append(
		os.Environ(),
		healthcheckHelperEnv+"=1",
		healthcheckHelperArgEnv+"="+arg,
		healthcheckHelperAddrEnv+"="+addr,
	)
	err := cmd.Run()
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		t.Fatalf("re-exec of test binary: %v", err)
	}
	return exitErr.ExitCode()
}

// TestMaybeHealthcheck_HealthyExitsZero pins the healthy contract: invoked as
// `<binary> healthcheck` against a 200 /healthz, the process exits 0.
func TestMaybeHealthcheck_HealthyExitsZero(t *testing.T) {
	t.Parallel()
	addr := healthzServer(t, http.StatusOK)
	if code := maybeHealthcheckExitCode(t, "healthcheck", addr); code != 0 {
		t.Fatalf("healthcheck against healthy server: exit %d, want 0", code)
	}
}

// TestMaybeHealthcheck_UnhealthyExitsOne pins the unhealthy contract: a non-200
// /healthz makes the probe process exit 1, which compose reads as unhealthy.
func TestMaybeHealthcheck_UnhealthyExitsOne(t *testing.T) {
	t.Parallel()
	addr := healthzServer(t, http.StatusServiceUnavailable)
	if code := maybeHealthcheckExitCode(t, "healthcheck", addr); code != 1 {
		t.Fatalf("healthcheck against 503 server: exit %d, want 1", code)
	}
}

// TestMaybeHealthcheck_NoArgIsNoOp pins the dispatch contract: without the
// healthcheck argument MaybeHealthcheck returns to the caller (the child then
// exits with the helper's own marker code), so a normal server start is never
// hijacked into a probe.
func TestMaybeHealthcheck_NoArgIsNoOp(t *testing.T) {
	t.Parallel()
	if code := maybeHealthcheckExitCode(t, "", ""); code != helperReturnedExit {
		t.Fatalf("no-arg invocation: exit %d, want %d (MaybeHealthcheck must return, not exit)", code, helperReturnedExit)
	}
}
