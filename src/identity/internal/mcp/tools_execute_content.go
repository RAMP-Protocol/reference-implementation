package mcp

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	mcpsdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/delivery"
)

// DefaultMaxCallContentBytes caps what ONE ramp_execute may accumulate across its
// whole batch, on top of the per-item cap the fetcher applies.
//
// The per-item cap alone does not bound a call: a batch fetches one body per
// item, every body is buffered whole, and all of them are base64-expanded by a
// third into a single JSON-RPC frame that lives until the call returns. Ten
// items at the item cap is already an order of magnitude more memory than any
// single fetch, and the batch size is the caller's choice. Items past the budget
// are reported as failures with their URLs intact, not silently dropped.
//
// It is a Config field rather than a constant for two reasons. An operator who
// raises the per-item cap needs to raise this with it or every batch silently
// collapses to one item — and while it was a constant, neither this budget nor
// the call deadline below could be driven by a test at all, so two tokens this
// service promises agents were unreachable.
const DefaultMaxCallContentBytes int64 = 32 << 20

// DefaultCallTimeout bounds ONE ramp_execute's whole content leg.
//
// The per-fetch timeout does not bound a call: items are fetched in sequence and
// the batch size is the caller's choice, so the worst case is N × the per-fetch
// timeout with N chosen by whoever is calling. Nothing upstream supplies a
// deadline — the MCP session's context carries none and the HTTP server sets only
// ReadHeaderTimeout — so without this the call is unbounded in wall time.
const DefaultCallTimeout = 2 * time.Minute

// budgetExhaustedReason is reported for an item skipped because the call's total
// content budget was already spent. It is deliberately distinct from the
// fetcher's own too_large: nothing is wrong with this item or its URL, and the
// agent may well succeed fetching it alone.
const budgetExhaustedReason = "call_budget_exhausted"

// callDeadlineReason is reported for an item the call ran out of time to fetch.
//
// Distinct from anything the fetch itself returns, for the same reason as the
// budget token: the edge was never asked, so reporting these as unreachable would
// turn one slow call into a batch of what read like publisher failures.
const callDeadlineReason = "call_deadline_exceeded"

// deliveryFailure reports one delivered item whose content this service could
// not hand over.
//
// It sits OUTSIDE items[] deliberately. An item is the protocol's own
// TransactionResultItem encoding, which the agent may hand back to us or to an
// Exchange; a field of ours inside it would corrupt bytes a signature covers.
// The correlation is offer_id, which every result item carries.
type deliveryFailure struct {
	// OfferID ties this failure back to its item.
	OfferID string `json:"offer_id"`
	// URL is the delivery URL that failed, repeated here so the agent can retry
	// the fetch itself without re-reading items[].
	URL string `json:"retrieval_endpoint"`
	// Reason is a machine-readable token: the edge's own refusal token when it
	// sent one (missing_agent_key, keyid_mismatch, pop_expired), otherwise the
	// failure class.
	Reason string `json:"reason"`
	// Message is the human-readable detail behind Reason.
	Message string `json:"message"`
}

// deliver fetches the content for every delivered item and returns the content
// blocks for the tool result. Failures are recorded on out; they are never
// returned as an error.
//
// THE INVARIANT: this cannot fail the call. By the time it runs the Exchange has
// already charged for the transaction, so refusing the result would bill the
// agent for content it never received AND deny it the URLs it could have used
// itself. Every failure path here therefore records and continues.
func (t *toolset) deliver(
	ctx context.Context, log *slog.Logger, who caller, in executeInput, out *executeOutput,
) []mcpsdk.Content {
	// The call's own deadline, applied HERE because this is the layer that knows
	// there is a call: the fetcher bounds one request and has no notion of a batch.
	// Without it the ctx.Err() branch below could only ever fire on a client
	// disconnect, which would make callDeadlineReason a token naming a deadline
	// nothing sets.
	ctx, cancel := context.WithTimeout(ctx, t.callTimeout)
	defer cancel()

	resources := make([]mcpsdk.Content, 0, len(out.Items))
	var spent int64
	for _, item := range out.Items {
		endpoint, _ := stringField(item, "retrieval_endpoint")
		if endpoint == "" {
			continue // a REFUSED item: nothing was licensed, so there is nothing to fetch
		}
		offerID, _ := stringField(item, "offer_id")
		if reason, message := t.skipReason(ctx, spent); reason != "" {
			out.DeliveryFailures = append(out.DeliveryFailures, deliveryFailure{
				OfferID: offerID, URL: endpoint, Reason: reason, Message: message,
			})
			continue
		}
		content, err := t.content.Fetch(ctx, endpoint)
		if err != nil {
			reason, message := deliveryReason(err)
			out.DeliveryFailures = append(out.DeliveryFailures, deliveryFailure{
				OfferID: offerID, URL: endpoint, Reason: reason, Message: message,
			})
			// The URL survives WHOLE in exactly one place: the failure's own
			// retrieval_endpoint field above, where the agent needs it to retry. Here
			// and in the message it is reduced, because a log line and a client's
			// forwarded diagnostics both outlive the credential in it — the rule the
			// edge applies to the same value on its own side.
			log.WarnContext(ctx, "identity.mcp.delivery_failed",
				"subdomain", who.subdomain, "offer_id", offerID, "reason", reason,
				"url", delivery.RedactURL(endpoint), "err", deliveryCause(err))
			continue
		}
		spent += int64(len(content.Body))
		resources = append(resources, embeddedResource(assetURI(in, offerID, content), content))
	}
	// The fallback goes FIRST so a client reading content[0].text still finds the
	// structured output where it has always been.
	return append(structuredFallback(*out), resources...)
}

// skipReason names why an item will not be fetched at all, or "" to go ahead.
//
// Both conditions are exhaustion of a CALL-scoped resource rather than anything
// wrong with the item: its URL is still valid and an agent may well succeed
// fetching it alone. They share a shape because they share that meaning — and
// keeping them in one place is what stops the loop growing a second nested
// branch each time the call gains a budget.
//
// The budget check is ANTICIPATORY — it asks whether the next body could still
// fit, not whether the previous ones already overflowed. Admitting an item whose
// worst case is the whole per-item cap and only then noticing the overrun makes
// the real ceiling budget + itemCap, so the number the budget's own doc comment
// promises would be one the process never honours.
func (t *toolset) skipReason(ctx context.Context, spent int64) (reason, message string) {
	if ctx.Err() != nil {
		return callDeadlineReason, "the call's deadline passed before this item was fetched"
	}
	if spent+t.maxItemContentBytes > t.maxCallContentBytes {
		return budgetExhaustedReason, "this call's total content budget was already spent"
	}
	return "", ""
}

// structuredFallback reproduces the text block the SDK adds on its own when a
// handler leaves Content unset.
//
// Setting Content at all suppresses that block (mcp/server.go only adds it when
// res.Content == nil), so attaching the resources would otherwise DELETE the
// JSON rendering of the output — and with it the delivery URLs, for every client
// that reads content[0].text rather than structuredContent. Re-adding it costs a
// second marshal of a small object.
//
// Returning nil on a marshal failure loses the JSON rendering rather than the
// resources: deliver appends the fetched blocks after this one, so Content is
// still non-nil whenever anything was fetched and the SDK adds nothing back. It
// is the lesser of two bad outcomes, not a fallback — and it is unreachable
// today, because every field of executeOutput comes from protojson and marshals.
// A future field with its own MarshalJSON is what would make it reachable.
func structuredFallback(out executeOutput) []mcpsdk.Content {
	encoded, err := json.Marshal(out)
	if err != nil {
		return nil
	}
	return []mcpsdk.Content{&mcpsdk.TextContent{Text: string(encoded)}}
}

// embeddedResource wraps fetched bytes as an MCP embedded resource.
//
// Blob, not Text, whatever the media type. ResourceContents.Text is a Go string,
// and encoding/json silently replaces invalid UTF-8 with U+FFFD rather than
// erroring — so routing a text/* body through it would corrupt paid-for content
// with no signal that anything happened. The media type rides along, so a client
// that wants characters decodes the blob with its own charset handling, which is
// where that decision belongs.
func embeddedResource(uri string, content delivery.Content) mcpsdk.Content {
	return &mcpsdk.EmbeddedResource{Resource: &mcpsdk.ResourceContents{
		URI:      uri,
		MIMEType: content.MIMEType,
		Blob:     content.Body,
	}}
}

// assetURI is the identity of the licensed resource, for the embedded
// resource's uri.
//
// It is the asset's own canonical URL, NOT the signed delivery URL. MCP's
// resource uri identifies the thing: clients de-duplicate on it, display it, and
// cite it. A delivery URL is a short-lived credential carrying sig, kid, exp and
// agent_id — putting it there would spray a live credential through every
// client's history, log and cache for the whole of its lifetime, and it goes
// stale in minutes besides, which makes it a poor identifier as well as an
// unsafe one.
//
// The canonical URL comes from the offer the caller submitted, correlated by
// offer_id; the result item does not carry one. When the offer names none, the
// delivery URL stripped of its query is the content's true location and carries
// no credential.
func assetURI(in executeInput, offerID string, content delivery.Content) string {
	if canonical := canonicalURLOf(in, offerID); canonical != "" {
		return canonical
	}
	// The fetcher's own redaction, not a second copy of it. The two had already
	// diverged — this one left userinfo in — and a weaker strip here is the worse
	// place for it: an embedded resource's uri is cached, displayed and cited by
	// clients, so anything it carries lives far longer than a log line.
	if stripped := delivery.RedactURL(content.URL); stripped != "" {
		return stripped
	}
	// Last resort: name the purchase rather than emit a URL we could not sanitize.
	return "urn:ramp:offer:" + offerID
}

// canonicalURLOf finds the submitted offer's canonical resource URL.
func canonicalURLOf(in executeInput, offerID string) string {
	if offerID == "" {
		return ""
	}
	for _, offer := range in.Offers {
		if id, _ := stringField(offer, "offer_id"); id != offerID {
			continue
		}
		identity, ok := offer["identity"].(map[string]any)
		if !ok {
			return ""
		}
		canonical, _ := stringField(identity, "canonical_url")
		return canonical
	}
	return ""
}

// stringField reads a string out of a decoded JSON object, reporting whether it
// was there and was in fact a string.
func stringField(obj map[string]any, key string) (string, bool) {
	value, ok := obj[key].(string)
	return value, ok
}
