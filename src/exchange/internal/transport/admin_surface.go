package transport

import (
	"log/slog"
	"net/http"

	"github.com/RAMP-Protocol/protocol/gen/go/ramp/admin/v1/rampadminv1connect"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampaudience"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// WrapAdminSurface assembles the admin control-plane HTTP surface shared by
// cmd/server (production) and the integration harness so both exercise ONE wiring:
// the emit-unpopulated JSON codec + the SDK bidirectional protovalidate interceptor
// (validates requests AND responses, per ADR-022 §2 and ADR-019) + NO request-signing,
// wrapped RequestID (outermost, so a rejected call still correlates) then IP-allowlist.
// The admin plane has no verified signer; the network allowlist is the only gate
// (ADR-022 §4). It is deliberately NOT wrapped by WrapPublicSurface and NOT mounted
// through the connectserver verify seam. An empty allowedCIDRs denies everything
// (fail-closed).
//
// The evidence read is mounted beside the Connect route as a plain JSON GET, so it
// carries neither the codec nor the protovalidate interceptor — it is not a protocol
// RPC. It shares the two middlewares, which is what confines it to this listener.
//
// audience travels with the shared mount options even though no admin message
// carries a recipient today. Passing it is what makes that a fact about the admin
// contract rather than an exemption this surface was granted: the day an admin
// request gains the field, it is already checked.
func WrapAdminSurface(
	logger *slog.Logger,
	svc *service.AdminService,
	evidence *service.EvidenceReadService,
	allowedCIDRs string,
	audience *rampaudience.Interceptor,
) (http.Handler, error) {
	opts, err := RawValidatedMountOptions(audience)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	path, h := rampadminv1connect.NewAdminServiceHandler(NewAdminHandler(svc), opts...)
	mux.Handle(path, h)
	// The method is part of the pattern, so net/http answers 405 for anything but
	// GET without a check in the handler.
	mux.HandleFunc("GET "+TransactionEvidencePath, transactionEvidenceHandler(evidence))

	allow, err := ParseAllowlist(allowedCIDRs)
	if err != nil {
		return nil, err
	}
	return RequestIDMiddleware(logger, IPAllowlistMiddleware(allow, mux)), nil
}
