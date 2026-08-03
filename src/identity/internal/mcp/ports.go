package mcp

import (
	"context"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/account"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/delivery"
)

// rampCaller is the outbound RAMP leg as this package uses it: five calls, no
// more. Declared here rather than imported as *rampclient.Client because the
// consumer is the one that knows how narrow the seam really is, and because a
// concrete struct in the field type makes the two packages inseparable for no
// benefit. *rampclient.Client satisfies it implicitly.
type rampCaller interface {
	Register(ctx context.Context, req *rampv1.RegisterRequest) (*rampv1.RegisterResponse, error)
	AccountStatus(ctx context.Context, req *rampv1.GetAccountStatusRequest) (*rampv1.GetAccountStatusResponse, error)
	Resolve(ctx context.Context, req *rampv1.DiscoveryRequest) (*rampv1.DiscoveryResponse, error)
	Execute(ctx context.Context, req *rampv1.TransactionRequest) (*rampv1.TransactionResponse, error)
	ReportUsage(ctx context.Context, exchangeDomain string, req *rampv1.UsageReport) (*rampv1.UsageReportResponse, error)
}

// contentFetcher is the content leg as this package uses it: fetch the bytes a
// signed delivery URL names, presenting the calling agent's custodied key. One
// method, and no way to ask for a different agent's key — the identity travels
// on the context, exactly as it does on the RAMP leg. *delivery.Fetcher
// satisfies it.
type contentFetcher interface {
	Fetch(ctx context.Context, signedURL string) (delivery.Content, error)
}

// developerReader is the one thing this package needs from the developer store:
// read the caller's own record. account.Store also offers Reserve and
// CompleteRegistration, and an adapter that only forwards licensing details at
// register time has no business holding a handle that can create accounts.
type developerReader interface {
	BySubdomain(ctx context.Context, subdomain string) (account.Developer, error)
}
