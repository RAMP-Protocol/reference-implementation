// Package main implements ramp-ledger: it renders the cryptographic evidence
// chain for one executed transaction by joining what three independent parties
// recorded about it, and re-verifies both Ed25519 proofs offline.
//
// The three sources never talk to each other, which is the whole point. The
// Exchange holds the signed offer and the agent's acceptance; the Broker holds
// what it offered that agent; the edge worker holds what it actually served.
// A chain that lines up across all three is evidence, because no single party
// could have produced it alone.
//
// Fetching and rendering are kept apart. Everything in this file and in
// assert.go and render.go is pure: it takes the three recorded views as data
// and returns the rendered chain, so the join semantics and the crypto are
// testable without an Exchange, a database, or AWS.
package main

import (
	"fmt"
	"net/http"
	"strconv"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/evidenceview"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// Sources is everything the three legs recorded, as fetched. Each leg beyond
// the Exchange may be absent: a missing Broker row or a missing delivery record
// weakens the chain but does not invalidate the part that is present, so the
// renderer states the gap and carries on. Only the Exchange leg is required —
// without the evidence row there is no transaction to render.
type Sources struct {
	Evidence         *evidenceview.Evidence
	Transaction      *evidenceview.TransactionState
	Obligation       *evidenceview.ObligationState
	Selection        *repo.SelectionLogEntry
	SelectionAbsence string
	Delivery         *DeliveryRecord
	DeliveryAbsence  string
}

// Row is one step of the chain as rendered: who recorded it, what they
// recorded, the identifier that joins it to its neighbours, and the
// cryptographic material backing it.
type Row struct {
	Party      string
	Step       string
	Event      string
	Correlator string
	Crypto     string
	// Absence explains why this step has no record, when it has none. A row
	// with an Absence carries no other content: the renderer prints the reason
	// in place of the step so a gap can never read as a recorded fact.
	Absence string
}

// Ledger is the rendered chain plus the assertions computed across it.
type Ledger struct {
	TransactionID string
	TenantID      string
	Rows          []Row
	Assertions    []Assertion
}

// BuildLedger joins the three views into the chain and computes every
// assertion. Rows are in the order the events happened, not the order the
// sources were read: the Exchange signs an offer before a Broker can offer it,
// and an agent accepts after being offered one.
func BuildLedger(s Sources) Ledger {
	return Ledger{
		TransactionID: s.Evidence.TransactionID,
		TenantID:      s.Evidence.TenantID,
		Rows: []Row{
			rowExchangeOffer(s),
			rowBrokerOffered(s),
			rowAgentAccepted(s),
			rowSignedURL(s),
			rowEdgeVerified(s),
			rowOriginServed(s),
			rowObligation(s),
		},
		Assertions: BuildAssertions(s),
	}
}

func rowExchangeOffer(s Sources) Row {
	e := s.Evidence
	return Row{
		Party:      "Exchange",
		Step:       "1. offer signed",
		Event:      fmt.Sprintf("issued and signed offer %s", e.OfferID),
		Correlator: "offer=" + e.OfferID,
		Crypto:     abbrev(e.OfferSigAlgorithm + " " + e.OfferSig),
	}
}

// rowBrokerOffered renders the Broker's own record of having put this offer in
// front of this agent. The Broker keeps no signature over its selection, so the
// crypto column states what actually backs the row: the offer id appearing in
// the candidate set the Broker recorded at the time.
func rowBrokerOffered(s Sources) Row {
	if s.Selection == nil {
		return Row{Party: "Broker", Step: "2. offer routed", Absence: s.SelectionAbsence}
	}
	sel := s.Selection
	return Row{
		Party: "Broker",
		Step:  "2. offer routed",
		Event: fmt.Sprintf("offered %s among %d candidates for %q",
			s.Evidence.OfferID, candidateCount(sel), sel.Query),
		Correlator: "req=" + sel.RequestID,
		Crypto:     "unsigned audit row",
	}
}

func rowAgentAccepted(s Sources) Row {
	e := s.Evidence
	return Row{
		Party:      "Agent " + e.RequesterDomain,
		Step:       "3. offer accepted",
		Event:      fmt.Sprintf("signed an acceptance as %s", e.RequesterID),
		Correlator: "idem=" + e.RequestIdempotencyKey,
		Crypto:     abbrev(e.AgentAcceptanceSignatureAlgorithm + " " + e.AgentAcceptanceSignature),
	}
}

// rowSignedURL renders the retrieval URL the Exchange minted. The URL itself is
// deliberately absent from the evidence contract — it stays a live bearer
// capability until it expires — so the row states its digest, which is also the
// value the delivery leg joins on.
func rowSignedURL(s Sources) Row {
	t := s.Transaction
	if len(t.SignedURLHash) == 0 {
		return Row{
			Party: "Exchange", Step: "4. URL minted",
			Absence: "no signed URL: this transaction delivered directly, so there is none to mint or expire",
		}
	}
	return Row{
		Party: "Exchange",
		Step:  "4. URL minted",
		Event: fmt.Sprintf("minted a signed retrieval URL, expiring %s",
			stamp(t.SignedURLExpiry)),
		Correlator: "idem=" + t.IdempotencyKey,
		Crypto:     abbrev("sha256 " + hexOf(t.SignedURLHash)),
	}
}

func rowEdgeVerified(s Sources) Row {
	if s.Delivery == nil {
		return Row{Party: "Edge", Step: "5. URL verified", Absence: s.DeliveryAbsence}
	}
	d := s.Delivery
	// The region is where the sweep found the record, not a field the worker
	// wrote. Lambda@Edge logs land in the point of presence that served the
	// request, so it names which POP answered — the one fact about the delivery
	// that is otherwise only recoverable by searching CloudWatch by hand.
	event := fmt.Sprintf("verified the signature on %s %s and authorized delivery", d.Method, d.Path)
	if d.Region != "" {
		event += ", served from " + d.Region
	}
	return Row{
		Party:      "Edge",
		Step:       "5. URL verified",
		Event:      event,
		Correlator: "req=" + d.RequestID,
		Crypto:     abbrev("sha256 " + d.URLHash),
	}
}

// originAnswered reports whether a delivery outcome means the origin returned a
// response before the edge record was written.
//
// It does not on every runtime, and the difference decides what this chain may
// claim. The Cloudflare and Fastly workers call fetch() and await the origin's
// response, then write the record. The AWS deployment attaches the worker at
// CloudFront's viewer-request event: the worker verifies the signature, writes
// its record, and hands the request back to CloudFront, which fetches the
// origin afterwards. On that path nothing this chain can read ever observed an
// origin response, and the outcome value says so itself.
//
// Unknown outcomes answer false deliberately. A rename on the worker side
// therefore weakens the claim rather than inventing one, which is the only
// direction a drift here is allowed to fail.
func originAnswered(outcome string) bool {
	// These strings are the worker's, in src/edge/src/app.ts. They are compared
	// rather than shared because the two sides are different languages.
	return outcome == "origin-forwarded" || outcome == "same-zone"
}

// rowOriginServed is derived from the SAME delivery record as row 5, not from
// an independent origin log, so a reader must not take it for a second witness.
// What it may assert depends on the outcome — see originAnswered. Where the
// origin was never observed the row stays with the Edge, because naming the
// Origin as the party of a row that reports no origin response would be the
// same overstatement one level down.
//
// Three claims, weakest first, and the row only makes the strongest one when the
// record earns it. The worker never saw a response (CloudFront hands the request
// back to the CDN): the row says the fetch was released. The worker waited but
// the record carries no usable status: the row says the origin answered and
// stops there, because fetch() resolves normally for 404 and 500. The worker
// waited and recorded a success status: only then does the row say content was
// served.
func rowOriginServed(s Sources) Row {
	if s.Delivery == nil {
		return Row{Party: "Origin", Step: "6. origin response", Absence: s.DeliveryAbsence}
	}
	d := s.Delivery
	if !originAnswered(d.Outcome) {
		return Row{
			Party: "Edge",
			Step:  "6. origin fetch released",
			Event: fmt.Sprintf(
				"released the request to the CDN for the origin fetch (%s); no origin response was observed by this witness",
				d.Outcome),
			Correlator: "req=" + d.RequestID,
			Crypto:     "—",
		}
	}
	if !originServedContent(d.OriginStatus) {
		return Row{
			Party: "Origin",
			Step:  "6. origin response observed",
			Event: fmt.Sprintf(
				"the origin answered via %s (per the edge record above, not a separate "+
					"origin log); %s, so this does not state that the content itself "+
					"was served",
				d.Outcome, statusPhrase(d.OriginStatus)),
			Correlator: "req=" + d.RequestID,
			Crypto:     "—",
		}
	}
	return Row{
		Party: "Origin",
		Step:  "6. content served",
		Event: fmt.Sprintf(
			"the origin served the content via %s, answering %s (per the edge "+
				"record above, not a separate origin log)",
			d.Outcome, d.OriginStatus),
		Correlator: "req=" + d.RequestID,
		Crypto:     "—",
	}
}

// originServedContent answers whether the recorded status is a success the row
// may call "content served".
//
// Every other answer is false, and the list of them is the point: a missing
// status (the worker never observed a response), a status that is not a number,
// a status outside 2xx, and a 2xx this code cannot parse all take the weaker
// branch. A drift on the worker side may only ever weaken this row, never
// promote it — the same fail-safe direction originAnswered uses. Promoting on a
// value nobody verified would put a claim in an evidence chain that no party
// made.
//
// 204 and 205 are deliberately excluded despite being 2xx: both mean the origin
// answered with NO body, so calling that "content served" would be false in the
// one way this row exists to avoid.
func originServedContent(status string) bool {
	code, err := strconv.Atoi(status)
	if err != nil {
		return false
	}
	return code >= 200 && code < 300 && code != http.StatusNoContent && code != http.StatusResetContent
}

// statusPhrase says why the row could not claim more, in the reader's terms.
// "No status" and "a 404" are different facts about the delivery and an operator
// reading a chain during a dispute needs to tell them apart.
func statusPhrase(status string) string {
	if status == "" {
		return "the record carries no origin status"
	}
	return fmt.Sprintf("the origin answered %s", status)
}

func rowObligation(s Sources) Row {
	o := s.Obligation
	if o == nil {
		return Row{
			Party: "Exchange", Step: "7. reporting",
			Absence: "no reporting obligation was minted for this transaction",
		}
	}
	return Row{
		Party:      "Exchange",
		Step:       "7. reporting",
		Event:      obligationEvent(o),
		Correlator: "tx=" + s.Evidence.TransactionID,
		Crypto:     "—",
	}
}

// obligationEvent prints the stored state verbatim. The persisted vocabulary is
// what a dispute reads off the row, so translating it here would let the word on
// screen differ from the word in the database.
//
// The consumed quantity is a decimal string because the column is
// NUMERIC(20,8); it is printed as given, since reparsing it as a number would
// truncate a fractional value the operator is entitled to see in full.
func obligationEvent(o *evidenceview.ObligationState) string {
	event := fmt.Sprintf("%s, due %s", o.State, stamp(&o.WindowEnd))
	if o.FulfilledAt != nil {
		event += ", fulfilled " + stamp(o.FulfilledAt)
	}
	if o.ConsumedQuantity != nil {
		event += ", " + *o.ConsumedQuantity + " consumed"
	}
	// The validation outcome is why an obligation still sitting at PENDING is
	// there: a report was filed and refused. Without it the operator reads the
	// same line for a refused report and for a transaction nobody ever
	// reported against, which is the question a dispute opens with. Lateness is
	// never the reason — a report is accepted however late — so the word here
	// is always a defect in the report itself.
	if o.ValidationOutcome != nil {
		event += ", " + *o.ValidationOutcome
		if o.ValidatedAt != nil {
			event += " " + stamp(o.ValidatedAt)
		}
	}
	return event
}

// candidateCount reports how many offers the Broker recorded having considered.
// The repository hands back a typed slice on the read path; anything else means
// the stored shape changed under us, and reporting 0 is the honest answer for a
// count this tool cannot take.
func candidateCount(sel *repo.SelectionLogEntry) int {
	candidates, ok := sel.CandidateOffers.([]repo.CandidateInfo)
	if !ok {
		return 0
	}
	return len(candidates)
}

// stamp renders a timestamp, or a dash when the source recorded none.
//
// The pointer is the parameter, and the nil check is inside on purpose. An
// earlier shape took the value plus a separate "present" flag, which every
// caller had to write as stamp(*p, p != nil) — and Go evaluates both arguments
// before the function body runs, so the dereference happened before the flag
// was ever read. That call panics on exactly the case the flag was there to
// handle. Taking the pointer makes the absent case unreachable by construction.
func stamp(t *time.Time) string {
	if t == nil {
		return "—"
	}
	return t.UTC().Format(time.RFC3339)
}

// cryptoColumnWidth is how much of a signature or digest the table shows.
// Enough to recognize a value at a glance; the assertions below the table carry
// every digest in full, so nothing a reader might copy is ever truncated.
const cryptoColumnWidth = 24

// abbrev shortens a long hex value for the table. Only the table truncates —
// the assertion details print the full value.
func abbrev(value string) string {
	if len(value) <= cryptoColumnWidth {
		return value
	}
	return value[:cryptoColumnWidth] + "…"
}
