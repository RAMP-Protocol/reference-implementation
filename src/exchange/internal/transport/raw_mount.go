package transport

import (
	"fmt"

	connect "connectrpc.com/connect"
	sdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience"
)

// RawValidatedMountOptions returns the handler options every RAW-mounted RAMP
// service shares: the emit-unpopulated JSON codec (keeps zero-valued scalars on the
// wire — the platform's snake_case JSON contract), the SDK bidirectional
// protovalidate interceptor (validates requests AND responses via
// helpers.SharedValidator — the SAME engine the ExchangeService path composes
// through connectserver.WithValidation, so the raw mounts cannot drift onto a
// forked ruleset), and the recipient check. The Catalog mount (through
// CatalogMountOptions below) and the admin mount (WrapAdminSurface) both build
// their options here so the set lives in exactly one place. A construction
// failure is a boot-time config fault: it is returned, and every caller threads
// it up the boot chain so the process exits non-zero.
//
// audience is required rather than optional. The catalog push is an addressed
// request like any other, so a raw mount without the check would be the one
// surface where naming a different Exchange still works — and a nil-means-skip
// parameter is exactly how that would happen quietly. Callers with no recipient
// to enforce do not exist; the admin mount passes the same interceptor and its
// own messages simply carry no recipient to check.
func RawValidatedMountOptions(audience *rampaudience.Interceptor) ([]connect.HandlerOption, error) {
	if err := rampaudience.Require(audience, "raw mount options"); err != nil {
		return nil, err
	}
	validateInterceptor, err := sdkconnect.NewValidateInterceptor()
	if err != nil {
		return nil, fmt.Errorf("validate interceptor: %w", err)
	}
	return []connect.HandlerOption{
		connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec()),
		connect.WithInterceptors(validateInterceptor, audience),
	}, nil
}

// CatalogMountOptions returns the handler options the raw CatalogService mount
// runs with: the shared raw-mount set from RawValidatedMountOptions plus the
// message read cap. Production (cmd/server) and the integration harness both
// call it, so the cap the tests drive is the cap that ships. Before this
// function existed the cap was appended by hand at each of those two sites,
// with no guard over either copy.
//
// The cap here bounds the DECOMPRESSED Connect message the handler decodes. It
// is one of the two quantities the ExchangeService mount pins through
// connectserver.WithMaxRequestBytes; the other, the raw body read before
// authentication, is bounded on this mount by CatalogSignatureMiddleware, which
// buffers the body for the per-contributor signature check. Both use
// MaxRPCReadBytes: the middleware refuses a raw body past it before
// verification, and the handler refuses a decoded message past it, which is how
// a small gzip body that inflates past the bound is still caught.
func CatalogMountOptions(audience *rampaudience.Interceptor) ([]connect.HandlerOption, error) {
	opts, err := RawValidatedMountOptions(audience)
	if err != nil {
		return nil, err
	}
	return append(opts, connect.WithReadMaxBytes(MaxRPCReadBytes)), nil
}
