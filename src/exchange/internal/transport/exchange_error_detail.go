package transport

import (
	"errors"

	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/connectserver"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/exchange"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/exchange/internal/service"
)

// exchangeServiceDomain is the ErrorInfo-compatible grouping key stamped onto
// ErrorDetail.Domain for every exchange fault (ADR-019). It mirrors the broker's
// brokerServiceDomain so a generic client reading ErrorDetail.domain attributes
// exchange and broker failures the same way.
const exchangeServiceDomain = "ramp.v1.ExchangeService"

// catalogServiceDomain is the same grouping key for the catalog surface. It is a
// separate service on the wire, so a client filtering on domain must be able to
// tell a catalog-push fault from an exchange one.
//
// Until this existed the catalog answered every fault through bare
// exchange.ToConnect, carrying no ErrorDetail at all — so ADR-019 §1's "every
// fault attributes via Domain" held for the exchange and the broker but not here,
// and any field metadata a catalog refusal set was computed and dropped.
const catalogServiceDomain = "ramp.v1.CatalogService"

// catalogFaultError maps a catalog error to its connect.Error and stamps the
// shared ErrorDetail envelope: Domain, the non-authoritative message, and any
// structured field metadata the domain error carries. It is genericFaultError's
// twin for the catalog surface — the catalog has no machine-readable reason
// oneof, so the generic shape is the whole shape here.
func catalogFaultError(err error) error {
	return faultEnvelope(err, catalogServiceDomain)
}

// txDenialReason returns the canonical DenialReason for a transaction-denial
// error, or ok=false when the failure is not a denial. It delegates to the
// service layer's single source of truth (service.DenialReasonForKind) so the
// single-offer transport detail and the batch per-item denial_reason share one
// vocabulary and cannot drift.
func txDenialReason(err error) (rampv1.DenialReason, bool) {
	return service.DenialReasonForKind(err)
}

// exchangeMeta returns the structured field metadata a service error recorded via
// exchange.Error.WithField, or nil when there is none. Per ADR-019 the offending
// field identity that the validator used to embed in the free-text message rides
// ErrorDetail.metadata, machine-readable, never the message. It is the single
// metadata-ride source both generic fault sinks share.
func exchangeMeta(err error) map[string]string {
	var de *exchange.Error
	if errors.As(err, &de) && len(de.Metadata) > 0 {
		return de.Metadata
	}
	return nil
}

// genericFaultError maps a service error to its connect.Error and stamps the
// shared ErrorDetail envelope (Domain + non-authoritative Message + any structured
// field metadata) with no typed reason oneof, via the shared SDK
// connectserver.AttachErrorDetail. It is the fault shape for the
// ExchangeService paths that carry no machine-readable reason — DiscoverResources
// and non-denial ExecuteTransaction — so EVERY ExchangeService fault attributes via
// ErrorDetail.Domain (ADR-019 §1), mirroring the broker stamping ramp.v1.BrokerService
// on every fault.
func genericFaultError(err error) error {
	return faultEnvelope(err, exchangeServiceDomain)
}

// faultEnvelope is the ONE place the shared envelope is built. Both surfaces
// stamp the same three things and differ only in the grouping key, so the domain
// is a parameter rather than a reason to write the body twice — a structural
// guard in this package pins that this call appears exactly once.
func faultEnvelope(err error, domain string) error {
	return connectserver.AttachErrorDetail(
		exchange.ToConnect(err), domain, err.Error(), exchangeMeta(err),
	)
}

// executeTxError maps a service error to its connect.Error. A transaction denial
// attaches the typed proto ErrorDetail carrying the canonical DenialReason — per
// ADR-019 the machine-readable reason travels as a typed detail (the same
// mechanism protovalidate uses for its violations), never a server-side string
// the client must parse — alongside Domain + the non-authoritative Message. The
// denial envelope is built by the shared SDK helpers.TransactionDenialDetail
// (which carries NO metadata — the machine-readable denial payload is the typed
// reason; field metadata rides only the generic path) and attached via the shared
// SDK connectserver.AttachDetail; a non-denial failure routes through
// genericFaultError so it still carries Domain.
func executeTxError(err error) error {
	reason, ok := txDenialReason(err)
	if !ok {
		return genericFaultError(err)
	}
	d := helpers.TransactionDenialDetail(exchangeServiceDomain, err.Error(), reason)
	return connectserver.AttachDetail(exchange.ToConnect(err), d)
}

// registerError maps a Register service error to its connect.Error. Register
// carries no machine-readable denial-reason oneof (unlike ExecuteTransaction), so
// it routes through genericFaultError — the shared fault shape that still stamps
// Domain + the non-authoritative Message so every ExchangeService fault
// attributes via ErrorDetail.Domain (ADR-019).
func registerError(err error) error {
	return genericFaultError(err)
}

// accountStatusError maps a GetAccountStatus service error to its connect.Error.
// Like Register, the status read carries no machine-readable denial-reason oneof,
// so it routes through the same shared fault shape (genericFaultError) that
// stamps Domain + the non-authoritative Message. It stays a distinct per-RPC
// mapper (mirroring registerError) to keep the file's one-mapper-per-RPC
// convention intact rather than sharing a single name across two RPCs.
func accountStatusError(err error) error {
	return genericFaultError(err)
}

// reportUsageError maps a ReportUsage service error to its connect.Error and
// attaches the shared no-reason ErrorDetail envelope. It delegates to
// genericFaultError so the ReportUsage fault shape has the SAME single source of
// truth as every other reasonless ExchangeService fault — the envelope body is
// never duplicated. The named seam is kept because the per-domain
// UsageReportRejection reason oneof is a separate ADR-019-completion step (tracked
// with the catalog CatalogRejectionReason adoption): when that lands, only this
// function grows the typed reason, mirroring executeTxError.
func reportUsageError(err error) error {
	return genericFaultError(err)
}
