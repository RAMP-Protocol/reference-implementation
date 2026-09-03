package mcp

import (
	"context"
	"fmt"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"
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
	const tool = "ramp_report"
	who, err := callerFrom(ctx, req)
	if err != nil {
		return nil, reportOutput{}, err
	}
	if in.Exchange, err = t.checkExchangeArg(tool, in.Exchange); err != nil {
		return nil, reportOutput{}, err
	}
	if err = in.validate(tool); err != nil {
		return nil, reportOutput{}, err
	}
	// The exchange rides on the report itself rather than beside it: the field is
	// the one the offer signed, and the leg below reads the destination from it.
	resp, err := t.reports.ReportUsage(t.callCtx(ctx, who), in.usageReport())
	if err != nil {
		return nil, reportOutput{}, t.failed(ctx, who, tool, err)
	}
	t.logger(ctx, who).InfoContext(ctx, "identity.mcp.report",
		"subdomain", who.subdomain, "exchange", in.Exchange,
		"transaction_id", in.TransactionID, "report_id", resp.GetReportId())
	return nil, reportOutput{ReportID: resp.GetReportId(), RequestID: who.requestID}, nil
}

// validate rejects a report that cannot be attributed. The idempotency key is
// required by the protocol, and required here rather than minted for the caller:
// a key we invent per call makes every retry look like a fresh report, which is
// exactly the double-counting the field exists to prevent.
//
// The exchange argument is not checked here. It is checked by the shared pair
// every tool taking one runs, before this, so the rule has one home rather than
// one per tool.
//
// tool is passed in for the same reason checkExchangeArg takes it: every message
// on this surface opens with the tool's name, and a literal per message is a
// place for one of them to be spelled differently from the rest.
func (in reportInput) validate(tool string) error {
	switch {
	case in.TransactionID == "":
		return fmt.Errorf("%s needs the transaction_id being reported", tool)
	case in.IdempotencyKey == "":
		return fmt.Errorf(
			"%s needs an idempotency_key — reuse it when retrying the same report", tool)
	}
	return nil
}

// usageReport builds the protocol message. The agent's identity is not on it:
// the Exchange takes that from the request signature, as it does everywhere else.
func (in reportInput) usageReport() *rampv1.UsageReport {
	report := &rampv1.UsageReport{
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: in.IdempotencyKey,
		TransactionId:  in.TransactionID,
		BillingId:      in.BillingID,
		// The recipient the agent means to report to. Required on the wire, and
		// set unconditionally: checkExchangeArg has already refused an empty or
		// non-bare value and canonicalised what survived, so there is no case
		// left where omitting it would be the honest thing to do. The Exchange
		// that receives it refuses a report naming somebody else.
		Exchange: in.Exchange,
		Usage: &rampv1.Usage{
			Function:         in.Function,
			ConsumedQuantity: in.ConsumedQuantity,
		},
		Assets: assets(in.Assets),
	}
	if in.ConsumedUnit != "" {
		report.Usage.ConsumedUnit = &in.ConsumedUnit
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
