package httpsig

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// The VERIFYING half of the agent-binding profile. The signer that used to sit
// beside it is gone: the protocol SDK ships one (helpers.SignAgentBinding), and
// the identity service — its only caller here — now uses it.
//
// Two functions remain, and they are the two halves of one thing: the builder
// that turns a request into the string a signature covers, and the reader that
// takes the freshness window back out of the header that carries it. They stay
// together because they are the same knowledge — a change to how this profile
// spells its parameters moves both. The header names travel with the SDK:
// helpers.AgentKeyHeader is the same constant this file used to declare, and a
// second declaration of a wire header is a rename upstream away from a verifier
// that keeps checking a value production no longer sends, with every test still
// passing.

// PoPSignatureBase builds the RFC 9421 signature base for the agent-binding
// profile: the two covered components followed by the parameters line, joined
// with newlines and with no trailing newline.
//
// It is exported because it is the one string every implementation of this
// profile must agree on byte for byte — the SDK's Go and TypeScript signers, the
// e2e harness's Python one, and this verifier are all pinned to the same vectors
// (testdata/pop-signature-base-vectors.json). A divergence in line order,
// quoting, or spacing rejects every bound fetch, and the symptom is an
// undifferentiated 403.
//
// rawParams is taken as given rather than rebuilt: it arrives verbatim in the
// Signature-Input header, and reconstructing it would mean guessing the
// parameter order a signer chose — which is exactly what this profile does
// differently from the rest of the package.
func PoPSignatureBase(method, rawURL, rawParams string) string {
	return strings.Join([]string{
		`"@method": ` + strings.ToUpper(method),
		`"@target-uri": ` + rawURL,
		`"@signature-params": ` + rawParams,
	}, "\n")
}

// popWindow finds the two freshness instants in a Signature-Input parameter
// list. Unanchored and matching only those two parameters, because the callers
// below ask one question — how long is this proof good for — of a header whose
// shape something else has already settled.
var popWindow = regexp.MustCompile(`created=(\d+);expires=(\d+)`)

// PoPWindowOf reads the created and expires instants out of a Signature-Input
// header, as unix seconds.
//
// It is here rather than in each caller because both callers were the same
// twelve lines: one match and two integer parses, differing only in the words
// they failed with. The difference between the two values IS the replay window a
// bound fetch can be repeated in, so a test that asserts anything about that
// lifetime reads it this way; jscpd never saw the copies, which sat under its
// floor and in two different packages.
//
// The enforcing edge double keeps a pattern of its own, and that is not a third
// copy to retire. Its expression is anchored across the WHOLE parameter list and
// answers "bad covered components" when it fails to match, so there the match is
// the covered-set check and it yields the keyid and the algorithm besides.
// Reading the two instants through this function would add a second parse
// without removing that one.
func PoPWindowOf(signatureInput string) (created, expires int64, err error) {
	m := popWindow.FindStringSubmatch(signatureInput)
	if m == nil {
		return 0, 0, fmt.Errorf("httpsig: no created/expires in Signature-Input %q", signatureInput)
	}
	if created, err = strconv.ParseInt(m[1], 10, 64); err != nil {
		return 0, 0, fmt.Errorf("httpsig: parse created in %q: %w", signatureInput, err)
	}
	if expires, err = strconv.ParseInt(m[2], 10, 64); err != nil {
		return 0, 0, fmt.Errorf("httpsig: parse expires in %q: %w", signatureInput, err)
	}
	return created, expires, nil
}
