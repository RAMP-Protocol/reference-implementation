package mcp

import (
	"context"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/core"
	"github.com/RAMP-Protocol/protocol/sdk/go/resolvers"
)

// The outbound legs arrive through a port each rather than through one
// interface, because they are served by different things and no single type
// satisfies all of them. Discovery, the usage report and the content fetch are
// the protocol SDK's. The purchase is still this repository's, because it goes
// to the Broker's relay route rather than to the ExchangeService RPC the SDK's
// Execute calls. Splitting them is what makes that division visible at the seam.
//
// The account workflow crosses no port in this file. Opening an account and
// asking after one are exchacct's, reached as that service rather than through a
// port here: a mirror interface repeating its methods would narrow nothing, and
// the layer below a transport is the one place this package is allowed to name
// concretely — the same seam oauthserver has on signup.Service. exchacct
// declares the outbound port those two RPCs travel on, next to the workflow that
// uses it.

// rampCaller is the part of the outbound leg this package still calls directly:
// the purchase, which goes to the Broker's relay route rather than to the
// ExchangeService RPC the SDK's Execute calls.
//
// It is one method because the account RPCs left. They are sent by exchacct now,
// through a port of its own, and a seam that still declared them here would
// widen this one past anything the tools reach for.
//
// Declared here rather than imported as *rampclient.Client because the consumer
// is the one that knows how narrow the seam really is, and because a concrete
// struct in the field type makes the two packages inseparable for no benefit.
type rampCaller interface {
	Execute(ctx context.Context, req *rampv1.TransactionRequest) (*rampv1.TransactionResponse, error)
}

// discoverer resolves offers through the Broker.
//
// It returns the verified/rejected split rather than the raw response, and that
// is the whole reason it is a distinct port: an agent on this surface runs no
// verifier of its own, so the offers it is shown have to have been checked here.
// A type returning the bare response could not express that.
type discoverer interface {
	Resolve(ctx context.Context, req *rampv1.DiscoveryRequest) (core.DiscoveryResult, error)
}

// reporter files a usage report with the Exchange that issued the offer.
//
// There is no exchange argument. The destination is read off the report's own
// exchange field, which the offer signed, and resolved from that Exchange's own
// manifest — so there is no parameter a configured origin could arrive as, which
// is what keeps the routing rule structural rather than conventional.
type reporter interface {
	ReportUsage(ctx context.Context, report *rampv1.UsageReport) (*rampv1.UsageReportResponse, error)
}

// contentFetch retrieves the bytes ONE signed delivery URL names, presenting the
// calling agent's custodied key.
//
// A function rather than an interface because the seam is one operation, and an
// alias rather than a defined type so the provider can name the same shape
// without either package importing the other.
type contentFetch = func(ctx context.Context, signedURL string) (resolvers.Content, error)

// contentFetcher opens the content leg for one purchase.
//
// It hands back a fetch rather than performing one, so a batch resolves the
// calling agent's key once and dials on one connection instead of once per item.
// Nothing here can ask for a different agent's key — the identity travels on the
// context, exactly as it does on the RAMP legs.
type contentFetcher interface {
	ContentSession(ctx context.Context) (contentFetch, error)
}

// exchangeAllowed answers whether this deployment will speak to an Exchange at
// all.
//
// A function rather than an interface because the seam is one question, matching
// contentFetch above. It is the same predicate the shared endpoint resolver
// carries, so the tool layer's readable refusal and the structural one below it
// cannot come to disagree.
type exchangeAllowed = func(domain string) bool
