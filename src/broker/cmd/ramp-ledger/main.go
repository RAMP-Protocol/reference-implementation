package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintf(os.Stderr, "ramp-ledger: %v\n", err)
		os.Exit(1)
	}
}

// Config is everything the three legs need. Endpoints and credentials come from
// flags and the environment only — nothing about a deployment is compiled in,
// so this binary carries no host, account or profile belonging to anyone.
type Config struct {
	TransactionID string
	AdminURL      string
	BrokerDBURL   string
	BrokerWindow  time.Duration
	EdgeLogGroup  string
	EdgeRegions   []string
	EdgeSkew      time.Duration
	Timeout       time.Duration
	AWS           AWSRunner
}

// defaultEdgeRegions are the points of presence swept for a delivery record
// when the operator names none. Lambda@Edge logs land in the region of the POP
// that served the request, so a sweep can only cover the places a run is likely
// to have been served from — this is not an exhaustive POP list, and a request
// served elsewhere needs its region added via the flag. The tool says so when
// it finds nothing rather than reporting the delivery as missing.
var defaultEdgeRegions = []string{
	"us-east-1", "us-east-2", "us-west-2",
	"eu-west-1", "eu-central-1", "eu-north-1",
	"ap-southeast-1", "ap-northeast-1",
}

func run(args []string, stdout io.Writer) error {
	cfg, err := parseConfig(args)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), cfg.Timeout)
	defer cancel()

	sources, err := Gather(ctx, cfg)
	if err != nil {
		return err
	}
	return Render(stdout, BuildLedger(sources))
}

func parseConfig(args []string) (Config, error) {
	fs := flag.NewFlagSet("ramp-ledger", flag.ContinueOnError)
	fs.Usage = func() {
		// A failure to write usage text to the already-failing output stream
		// leaves nothing useful to do, so the error is discarded deliberately.
		_, _ = fmt.Fprint(fs.Output(), usage)
		fs.PrintDefaults()
	}
	tx := fs.String("tx", os.Getenv("TX"), "transaction id to render (required)")
	adminURL := fs.String("admin-url", os.Getenv("RAMP_ADMIN_URL"),
		// 8082 is the Exchange's ADMIN_ADDR default, so a tunnel that forwards
		// the admin port unchanged lands here. An operator reads this line while
		// the demo is running; a port that matches nothing costs them the time
		// it takes to go and look it up.
		"Exchange admin base URL, typically a local tunnel, e.g. http://127.0.0.1:8082")
	brokerDB := fs.String("broker-db", os.Getenv("BROKER_DB_URL"),
		"Broker Postgres DSN, typically through a tunnel; omit to skip the routing leg")
	logGroup := fs.String("edge-log-group", os.Getenv("RAMP_EDGE_LOG_GROUP"),
		"CloudWatch log group of the edge function; omit to skip the delivery leg")
	regions := fs.String("edge-regions", os.Getenv("RAMP_EDGE_REGIONS"),
		"comma-separated regions to sweep for the delivery record")
	window := fs.Duration("broker-window", time.Hour,
		"how far before the transaction to look for the Broker's routing decision")
	skew := fs.Duration("edge-skew", 5*time.Minute,
		"clock-skew margin applied before the transaction when searching edge logs")
	timeout := fs.Duration("timeout", 2*time.Minute, "overall deadline for the whole run")
	if err := fs.Parse(args); err != nil {
		return Config{}, err
	}

	cfg := Config{
		TransactionID: *tx, AdminURL: *adminURL,
		BrokerDBURL: *brokerDB, BrokerWindow: *window,
		EdgeLogGroup: *logGroup, EdgeRegions: splitRegions(*regions), EdgeSkew: *skew,
		Timeout: *timeout, AWS: CLIRunner{},
	}
	return cfg, validate(cfg)
}

// validate refuses only what makes the run impossible. A missing Broker DSN or
// edge log group is a narrower chain, not an error: the operator may not have a
// tunnel open, and the rendered gap says which leg is missing and why.
func validate(cfg Config) error {
	var missing []string
	if cfg.TransactionID == "" {
		missing = append(missing, "-tx / TX")
	}
	if cfg.AdminURL == "" {
		missing = append(missing, "-admin-url / RAMP_ADMIN_URL")
	}
	if len(missing) > 0 {
		return fmt.Errorf("missing required settings: %s", strings.Join(missing, ", "))
	}
	return nil
}

func splitRegions(raw string) []string {
	if strings.TrimSpace(raw) == "" {
		return defaultEdgeRegions
	}
	var out []string
	for _, part := range strings.Split(raw, ",") {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	if len(out) == 0 {
		return defaultEdgeRegions
	}
	return out
}

const usage = `ramp-ledger renders the cryptographic evidence chain for one executed
RAMP transaction, joining three independent records of it:

  the Exchange   the signed offer, the agent's acceptance, and both proofs
  the Broker     its own audit of having offered that offer to that agent
  the edge       the delivery it authorized, joined on the signed URL's digest

Both Ed25519 signatures are re-verified offline, from the stored bytes and the
stored keys, with no live service involved.

The Exchange admin plane and the Broker database are reachable from inside a
deployment only, so both are normally addressed through a tunnel. The edge leg
shells out to the aws CLI and uses whatever credentials it already resolves.

  ramp-ledger -tx <transaction-id>

`
