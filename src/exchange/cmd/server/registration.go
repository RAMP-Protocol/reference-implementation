package main

import (
	"fmt"
	"log/slog"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/runhttp"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/regschema"
)

// registrationConfig groups the operator's registration settings: the schema an
// agent's registration_data must match, and the terms document a registration
// accepts, pinned by digest.
//
// It is read ONCE, by the single loadRegistrationConfig call below, and that is
// the whole point. These values have two readers — the manifest that publishes
// them, and the Register gate that holds a caller to them — and an Exchange that
// advertised one shape while refusing on another, or published one terms
// revision while checking registrations against a different one, would be wrong
// in a way neither reader could detect on its own. Both readers take this same
// value: buildExchange threads the schema into ExchangeDeps.RegSchema and the
// digest into ExchangeConfig.TermsDigest, and neither loads its own. Structural
// guards under internal/guards keep every route to a second value — a second
// regschema.Load, a direct call to the SDK compile face, a second read of
// either environment variable — to this one file.
//
// Every field is optional and unset means unchanged behaviour: no schema
// published and registration_data passed through uninspected, no terms
// versioning, which is how every deployment behaved before these existed.
type registrationConfig struct {
	schema      *regschema.Schema
	termsURI    string
	termsDigest string
}

// loadRegistrationConfig reads the three settings from the environment and
// reports what it resolved, the way every other loader in this root does. An
// operator who mistypes a variable name otherwise gets a silent boot and a
// manifest with no block, which reads exactly like a deployment that never
// configured one.
//
// A configured but unusable schema is returned as an error and run() refuses to
// start on it. That is deliberate and not defensive: a schema dropped with a
// log line would leave the Exchange publishing nothing while its operator
// believed the requirement was published, and the first evidence would be a
// registration arriving without the details that were asked for.
//
// The terms values are read trimmed so a variable holding only whitespace reads
// as unset rather than being published verbatim — the same answer the SDK gives
// for a whitespace-only schema. Their shape is checked against the protocol's
// protovalidate constraints when the document is built, so a malformed digest
// fails the same boot.
func loadRegistrationConfig(logger *slog.Logger) (registrationConfig, error) {
	schema, err := regschema.Load(runhttp.EnvOr("EXCHANGE_REGISTRATION_SCHEMA", ""))
	if err != nil {
		return registrationConfig{}, fmt.Errorf("registration: invalid EXCHANGE_REGISTRATION_SCHEMA: %w", err)
	}
	cfg := registrationConfig{
		schema:      schema,
		termsURI:    runhttp.EnvTrimmed("EXCHANGE_TERMS_URI"),
		termsDigest: runhttp.EnvTrimmed("EXCHANGE_TERMS_DIGEST"),
	}
	// The digest is logged as its value, not as a boolean. It is a public hash
	// this Exchange publishes to every agent, so there is nothing to withhold,
	// and it is the half an operator mistypes — an operator told only that a
	// digest is published cannot see why agents are being pointed at the wrong
	// revision. The schema stays a boolean because it is a whole document, too
	// long for a boot line, and the served manifest is where to read it back.
	logger.Info("registration settings resolved",
		"registration_schema_published", cfg.schema != nil,
		"terms_uri", cfg.termsURI,
		"terms_digest", cfg.termsDigest)
	return cfg, nil
}
