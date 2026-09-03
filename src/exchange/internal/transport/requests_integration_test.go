//go:build integration

package transport_test

import (
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
	"google.golang.org/protobuf/types/known/structpb"
)

// The request envelope every message in this package repeats: the protocol
// version, and the Exchange these tests address.
//
// One required field cost this package 179 hand edits, because each of the
// messages below was written out at its call sites — 63 pushes, 43 reports, 19
// queries, 50 requesters and 37 account calls, each restating what never
// varies. The builders put
// the envelope in one place; a message with something deliberately wrong in it
// keeps its literal, because that IS the test.
//
// The file carries the integration tag because every caller does: the lint pass
// runs without tags, and a helper it can see but no caller can is reported as
// dead. One untagged test drives a handler below the mount and writes its own
// literal for that reason.
//
// Every builder returns the message rather than sending it, so a caller that
// needs one more field sets it on the result. That keeps the parameter lists at
// what actually varies instead of growing an argument per rare case.

// newPushRequest builds a catalog push under tenantID, sent as callerID.
func newPushRequest(
	tenantID, callerID string, entries []*rampv1.ResourceEntry,
) *rampv1.PushResourcesRequest {
	return &rampv1.PushResourcesRequest{
		Exchange: harnessExchangeDomain,
		Ver:      helpers.ProtocolVersion,
		TenantId: tenantID,
		CallerId: callerID,
		Entries:  entries,
	}
}

// newUsageReport builds a report against the obligation transactionID names.
// billingID is empty for an obligation that carries none.
func newUsageReport(
	idempotencyKey, transactionID, billingID string, usage *rampv1.Usage,
) *rampv1.UsageReport {
	return &rampv1.UsageReport{
		Exchange:       harnessExchangeDomain,
		Ver:            helpers.ProtocolVersion,
		IdempotencyKey: idempotencyKey,
		TransactionId:  transactionID,
		BillingId:      billingID,
		Usage:          usage,
	}
}

// newResourceQuery builds a discovery query for uris on behalf of requester.
func newResourceQuery(requester *rampv1.Requester, uris []string) *rampv1.ResourceQuery {
	return &rampv1.ResourceQuery{
		Exchange:  harnessExchangeDomain,
		Ver:       helpers.ProtocolVersion,
		Uris:      uris,
		Requester: requester,
	}
}

// newRegisterRequest builds an agent registration. data is the free-form
// registration payload the agent supplies; nil for a registration that carries
// none, which is the common case in these tests.
func newRegisterRequest(data *structpb.Struct) *rampv1.RegisterRequest {
	return newRegisterRequestWithTerms(data, "")
}

// newRegisterRequestWithTerms is newRegisterRequest naming the terms revision
// the caller accepts. An empty digest leaves the field unset, which is the
// "accepted nothing" case an Exchange publishing a digest refuses.
func newRegisterRequestWithTerms(data *structpb.Struct, termsDigest string) *rampv1.RegisterRequest {
	req := &rampv1.RegisterRequest{
		Exchange:         harnessExchangeDomain,
		Ver:              helpers.ProtocolVersion,
		RegistrationData: data,
	}
	// The field is optional on the wire, so an empty digest leaves it UNSET
	// rather than sending an empty string. Those are different messages, and
	// "sent nothing" is the case the terms gate has to answer.
	if termsDigest != "" {
		req.TermsDigest = &termsDigest
	}
	return req
}

// newAccountStatusRequest builds the account-status call. The message carries
// nothing else on purpose: the Exchange resolves the account from the verified
// signature, so the envelope IS the request.
func newAccountStatusRequest() *rampv1.GetAccountStatusRequest {
	return &rampv1.GetAccountStatusRequest{
		Exchange: harnessExchangeDomain,
		Ver:      helpers.ProtocolVersion,
	}
}

// newRequester builds the agent identity a query or an execute carries.
func newRequester(id, domain string, scopes ...string) *rampv1.Requester {
	return &rampv1.Requester{
		Id:     id,
		Domain: domain,
		Type:   rampv1.RequesterType_REQUESTER_TYPE_AGENT,
		Scopes: scopes,
	}
}
