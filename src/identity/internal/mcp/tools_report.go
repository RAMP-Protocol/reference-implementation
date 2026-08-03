package mcp

import (
	"context"
	"errors"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	rampproto "gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/proto"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/rampwellknown"
)

// reportInput describes one usage report.
//
// Exchange is the routing input, and it is deliberately the offer's `exchange`
// DOMAIN rather than a URL: the endpoint is resolved from that Exchange's own
// well-known manifest, never from something the caller supplies. A caller that
// could name the endpoint could point a report — and the agent's signature on it —
// at a host of its choosing.
type reportInput struct {
	// Exchange is the `exchange` domain carried on the offer that was licensed.
	Exchange string `json:"exchange"`
	// TransactionID is the Exchange-assigned id of the transaction being reported.
	TransactionID string `json:"transaction_id"`
	// BillingID is the billing reference returned alongside that transaction.
	BillingID string `json:"billing_id,omitempty"`
	// IdempotencyKey makes a retried report safe: the Exchange dedupes on it and
	// returns the original result rather than double-counting. Supply the same
	// value when retrying the same report.
	IdempotencyKey string `json:"idempotency_key"`
	// Function is the RSL usage vocabulary describing what the content was used
	// for — e.g. "ai-input", "ai-train", "search".
	Function []string `json:"function,omitempty"`
	// ConsumedQuantity is how much was consumed, in ConsumedUnit.
	ConsumedQuantity int32 `json:"consumed_quantity,omitempty"`
	// ConsumedUnit names the unit ConsumedQuantity counts in.
	ConsumedUnit string `json:"consumed_unit,omitempty"`
	// Assets lists the specific resources this report covers.
	Assets []reportAsset `json:"assets,omitempty"`
}

// reportAsset is one resource covered by a report.
type reportAsset struct {
	URI       string `json:"uri"`
	Title     string `json:"title,omitempty"`
	PackageID string `json:"package_id,omitempty"`
}

// reportOutput is the UsageReportResponse projection.
type reportOutput struct {
	// ReportID is the Exchange's handle for the accepted report.
	ReportID string `json:"report_id"`
	// RequestID is the correlation id this call ran under, quotable in a bug
	// report. Every tool returns it, so an agent never has to know which of the
	// five happens to carry one.
	RequestID string `json:"request_id,omitempty"`
}

// handleReport sends a usage report straight to the Exchange that issued the
// offer — never through the Broker.
//
// Routing directly is the point: the Broker has no part to play in reporting, and
// the report must reach the Exchange holding the obligation. That Exchange is
// found from the offer's signed `exchange` domain via its own
// /.well-known/ramp.json, which keeps the registry from being able to redirect a
// report anywhere by configuration.
func (t *toolset) handleReport(
	ctx context.Context, req *mcpsdk.CallToolRequest, in reportInput,
) (*mcpsdk.CallToolResult, reportOutput, error) {
	who, err := callerFrom(ctx, req)
	if err != nil {
		return nil, reportOutput{}, err
	}
	if err = in.validate(); err != nil {
		return nil, reportOutput{}, err
	}
	resp, err := t.ramp.ReportUsage(who.outbound(ctx), in.Exchange, in.usageReport())
	if err != nil {
		return nil, reportOutput{}, rampError("ramp_report", err)
	}
	t.logger(ctx, who).InfoContext(ctx, "identity.mcp.report",
		"subdomain", who.subdomain, "exchange", in.Exchange,
		"transaction_id", in.TransactionID, "report_id", resp.GetReportId())
	return nil, reportOutput{ReportID: resp.GetReportId(), RequestID: who.requestID}, nil
}

// validate rejects a report that cannot be routed or attributed. The
// idempotency key is required by the protocol, and required here rather than
// minted for the caller: a key we invent per call makes every retry look like a
// fresh report, which is exactly the double-counting the field exists to prevent.
func (in reportInput) validate() error {
	switch {
	case in.Exchange == "":
		return errors.New("ramp_report needs the offer's exchange domain")
	case in.TransactionID == "":
		return errors.New("ramp_report needs the transaction_id being reported")
	case in.IdempotencyKey == "":
		return errors.New("ramp_report needs an idempotency_key — reuse it when retrying the same report")
	}
	return validateExchangeDomain(in.Exchange)
}

// validateExchangeDomain enforces the one thing the Exchange field's contract
// already claimed: it is a DOMAIN, not a URL.
//
// The value is routing input that reaches URL construction downstream — the
// well-known endpoint resolver builds {scheme}://{exchange}/.well-known/ramp.json
// by concatenation — so a caller that can smuggle a path, query, or fragment past
// this point picks the URL this service fetches rather than merely the host it
// fetches from. Checking the value against its own normalized host is what makes
// that structural: anything HostOf had to strip is something a domain never had.
//
// Refused rather than narrowed to the host, deliberately. Narrowing would let a
// caller send a request this service silently rewrote, and the report is a
// billing artifact — the agent should learn its input was wrong here, not have it
// quietly reinterpreted.
func validateExchangeDomain(exchange string) error {
	bare, err := rampwellknown.IsBareHost(exchange)
	if err != nil {
		return fmt.Errorf("ramp_report: exchange %q is not a usable domain: %w", exchange, err)
	}
	if !bare {
		return fmt.Errorf(
			"ramp_report: exchange must be the offer's bare domain (\"exchange.example\" or "+
				"\"exchange.example:8081\"), not %q — a scheme, path, query or fragment is not part of it",
			exchange,
		)
	}
	return nil
}

// usageReport builds the protocol message. The agent's identity is not on it:
// the Exchange takes that from the request signature, as it does everywhere else.
func (in reportInput) usageReport() *rampv1.UsageReport {
	report := &rampv1.UsageReport{
		Ver:            rampproto.Ver,
		IdempotencyKey: in.IdempotencyKey,
		TransactionId:  in.TransactionID,
		BillingId:      in.BillingID,
		Usage: &rampv1.Usage{
			Function:         in.Function,
			ConsumedQuantity: in.ConsumedQuantity,
		},
		Assets: assets(in.Assets),
	}
	if in.ConsumedUnit != "" {
		report.Usage.ConsumedUnit = &in.ConsumedUnit
	}
	if in.Exchange != "" {
		report.Exchange = &in.Exchange
	}
	return report
}

// assets converts the reported resources to their protocol form.
func assets(in []reportAsset) []*rampv1.UsageAsset {
	if len(in) == 0 {
		return nil
	}
	out := make([]*rampv1.UsageAsset, 0, len(in))
	for _, a := range in {
		asset := &rampv1.UsageAsset{Uri: a.URI}
		if a.Title != "" {
			asset.Title = &a.Title
		}
		if a.PackageID != "" {
			asset.PackageId = &a.PackageID
		}
		out = append(out, asset)
	}
	return out
}
