package registry

import _ "embed"

// DefaultBootstrap is the bundled bootstrap.yaml used as a starting point
// when no BROKER_REGISTRY_FILE is configured at startup.
//
//go:embed bootstrap.yaml
var DefaultBootstrap []byte
