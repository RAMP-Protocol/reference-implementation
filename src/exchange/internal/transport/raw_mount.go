package transport

import (
	"fmt"

	connect "connectrpc.com/connect"
	sdkconnect "github.com/RAMP-Protocol/protocol/sdk/go/connect"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
)

// RawValidatedMountOptions returns the two handler options every RAW-mounted RAMP
// service shares: the emit-unpopulated JSON codec (keeps zero-valued scalars on the
// wire — the platform's snake_case JSON contract) and the SDK bidirectional
// protovalidate interceptor (validates requests AND responses via
// helpers.SharedValidator — the SAME engine the ExchangeService path composes
// through connectserver.WithValidation, so the raw mounts cannot drift onto a
// forked ruleset). Both the Catalog mount (cmd/server) and the admin mount
// (WrapAdminSurface) build their options here so the pair lives in exactly one
// place. A construction failure is a boot-time config fault: it is returned, and
// every caller threads it up the boot chain so the process exits non-zero.
func RawValidatedMountOptions() ([]connect.HandlerOption, error) {
	validateInterceptor, err := sdkconnect.NewValidateInterceptor()
	if err != nil {
		return nil, fmt.Errorf("validate interceptor: %w", err)
	}
	return []connect.HandlerOption{
		connect.WithCodec(connectserver.EmitUnpopulatedJSONCodec()),
		connect.WithInterceptors(validateInterceptor),
	}, nil
}
