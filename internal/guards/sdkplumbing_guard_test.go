// Package guards holds repo-wide structural guard tests. This file pins the
// "hand-rolled L2 transport plumbing" disease closed: the emit-unpopulated
// Connect codec and the RFC 9421 signing RoundTripper live in the RAMP SDK
// (sdk/go/connectserver.EmitUnpopulatedJSONCodec, sdk/go/core.NewSigningTransport)
// — app code must not re-implement either. All app sign calls now route
// through the SDK signing transport; no app-side transport is sanctioned.
// forbiddenPaths additionally keeps the Exchange's retired license-term package
// deleted: its canonicalization and ingest-tier checks are sdk/go/helpers now.
package guards

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

// emitUnpopulatedLiteral matches a protojson MarshalOptions composite literal
// that sets EmitUnpopulated — the shape of a hand-rolled emit-unpopulated
// codec. It is content-anchored (NOT import-alias-anchored) so an aliased
// import (pj.MarshalOptions{...}) or a multi-line literal cannot slip it; a
// call to the SDK's EmitUnpopulatedJSONCodec() does not match because no
// MarshalOptions literal appears at the call site.
var emitUnpopulatedLiteral = regexp.MustCompile(`(?s)MarshalOptions\{[^}]*EmitUnpopulated`)

// signHelperCall matches production code invoking the SDK sign helpers
// directly — the body of a hand-rolled signing RoundTripper. Only the
// canonical transport may do this.
var signHelperCall = regexp.MustCompile(`helpers\.(SignRequest|AppendSignature)\(`)

// signHelperAllowlist names the non-test files sanctioned to call the sign
// helpers. The app otherwise collapsed onto sdk/go/core.NewSigningTransport;
// each entry below is a justified exception, not a general licence.
var signHelperAllowlist = map[string]bool{
	// The identity service signs one outbound leg per AGENT, with the key
	// custody resolves for that request. core.NewSigningTransport binds ONE
	// helpers.Signer for the life of the transport and Signer.KeyID() takes
	// neither a request nor a context, so a per-request keyid cannot be expressed
	// through it — and one transport per agent is not an option for a service that
	// fronts every agent. This file therefore calls the sign helpers directly.
	//
	// It does NOT re-derive a signature base: the RAMP covered set, the canonical
	// bytes and the chain linkage are all the SDK's. The one thing that stays local
	// is the Web Bot Auth profile, which signs @authority instead of @target-uri —
	// SignOptions exposes no covered-set control, so the SDK cannot express it.
	"internal/ramphttpsig/transport.go": true,
}

// ed25519SignCall matches production code calling the stdlib Ed25519 signer
// directly — the load-bearing token of every hand-rolled signature production
// (signed URLs, offers, requests). The canonical homes are the SDK helpers;
// app code composes those. A raw "GET\n" canonical-prefix ban is deliberately
// NOT used: it false-positives on doc comments and a hand-roll cannot sign
// without this call anyway.
var ed25519SignCall = regexp.MustCompile(`ed25519\.Sign\(`)

// ed25519SignAllowlist names the non-test files sanctioned to call
// ed25519.Sign directly. cosign.go is the broker's detached forwarding-chain
// signature — a distinct wire contract (X-RAMP-Broker-Signature) with no SDK
// equivalent face.
var ed25519SignAllowlist = map[string]bool{
	"src/broker/internal/signing/cosign.go": true,
}

// jcsTransformCall matches production code invoking RFC 8785 canonicalization
// directly — the body of a hand-rolled canonical-signing payload. The JCS
// switch lives inside the SDK (helpers canonicalSignPayload); app code signs
// and verifies through the SDK faces. The primary gate is the depguard deny
// rule on github.com/gowebpki/jcs in .golangci.yml; this guard is the
// belt-and-suspenders structural check.
var jcsTransformCall = regexp.MustCompile(`jcs\.Transform\(|"github\.com/gowebpki/jcs"`)

// jcsAllowlist is EMPTY: no app file is sanctioned to canonicalize directly.
// The mechanism stays so a future, justified exception is a one-line entry.
var jcsAllowlist = map[string]bool{}

// forbiddenPaths are the deleted homes of app-side copies of SDK-owned logic:
// the transport plumbing above, and the license-term canonicalization and
// ingest-tier checks the Exchange once kept in its own package and now imports
// from sdk/go/helpers. Their resurrection is a regression regardless of
// content.
var forbiddenPaths = []string{
	"internal/rampcodec",
	"internal/signingtransport",
	"internal/sigwindow",
	"src/exchange/internal/transport/jsoncodec.go",
	"src/broker/internal/transport/jsoncodec.go",
	"src/exchange/internal/licenseterm",
}

// repoRoot walks up from the working directory to the go.mod root.
func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from test dir")
		}
		dir = parent
	}
}

// appSourceFiles yields every non-test, non-generated .go file under src/ and
// internal/, as repo-root-relative paths. Guards that bind production code use
// this; one that must also read fixtures calls appSourceAndTestFiles instead, so
// widening that guard cannot silently widen these.
func appSourceFiles(t *testing.T, root string) []string {
	t.Helper()
	return appGoFiles(t, root, false)
}

// appSourceAndTestFiles yields the same set plus _test.go files. Only the ver
// guard wants this: every "0.3" this project ever shipped was in a fixture, so a
// check that skipped them could not have caught one.
func appSourceAndTestFiles(t *testing.T, root string) []string {
	t.Helper()
	return appGoFiles(t, root, true)
}

// appGoFiles walks src/ and internal/ through the single filter every guard
// shares, so the definition of "a file this repo owns" has one home.
func appGoFiles(t *testing.T, root string, includeTests bool) []string {
	t.Helper()
	tops := []string{"src", "internal"}
	files := make([]string, 0, len(tops))
	for _, top := range tops {
		files = append(files, goSourceFilesUnder(t, root, top, includeTests)...)
	}
	return files
}

// assertNoMatchOutsideAllowlist fails for every app source file outside
// allowlist whose bytes match re, reporting msg with the offending path.
//
// Five guards in this package scan the same way — walk appSourceFiles, skip the
// allowlist, read, match, report — and three values are all that differ between
// them. Written out per guard, the copies drift in ways that mean nothing: one
// of them converted an already-slash-form path again before indexing its
// allowlist, which reads to the next person as a difference that matters.
func assertNoMatchOutsideAllowlist(t *testing.T, re *regexp.Regexp, allowlist map[string]bool, msg string) {
	t.Helper()
	root := repoRoot(t)
	for _, rel := range appSourceFiles(t, root) {
		if allowlist[rel] {
			continue
		}
		src, err := os.ReadFile(filepath.Join(root, rel))
		if err != nil {
			t.Fatalf("read %s: %v", rel, err)
		}
		if re.Match(src) {
			t.Errorf("%s %s", rel, msg)
		}
	}
}

// TestNoHandRolledEmitUnpopulatedCodec fails when any app source file
// constructs a protojson MarshalOptions literal with EmitUnpopulated — the
// codec belongs to sdk/go/connectserver, never to app code.
func TestNoHandRolledEmitUnpopulatedCodec(t *testing.T) {
	t.Parallel()
	assertNoMatchOutsideAllowlist(t, emitUnpopulatedLiteral, nil,
		"constructs an EmitUnpopulated MarshalOptions literal — use sdk/go/connectserver.EmitUnpopulatedJSONCodec() / WithEmitUnpopulated() instead")
}

// TestNoHandRolledSigningRoundTripper fails when a non-allowlisted app source
// file calls the SDK sign helpers directly — signing transports come from the
// SDK (core.NewSigningTransport) or the single canonical app transport.
func TestNoHandRolledSigningRoundTripper(t *testing.T) {
	t.Parallel()
	assertNoMatchOutsideAllowlist(t, signHelperCall, signHelperAllowlist,
		"calls helpers.SignRequest/AppendSignature directly — compose the SDK signing transport (sdk/go/core.NewSigningTransport) instead")
}

// TestNoHandRolledEd25519Sign fails when a non-allowlisted app source file
// calls ed25519.Sign directly — signature production (signed URLs, offers,
// requests) lives behind the SDK faces.
func TestNoHandRolledEd25519Sign(t *testing.T) {
	t.Parallel()
	assertNoMatchOutsideAllowlist(t, ed25519SignCall, ed25519SignAllowlist,
		"calls ed25519.Sign directly — sign through the SDK faces (helpers.SignURLEd25519 / SignOffer / core.NewSigningTransport)")
}

// TestNoHandRolledJCSCanonicalization fails when any app source file imports
// gowebpki/jcs or calls jcs.Transform — canonical signing payloads are
// SDK-owned. (depguard carries the same ban at lint time; see .golangci.yml.)
func TestNoHandRolledJCSCanonicalization(t *testing.T) {
	t.Parallel()
	assertNoMatchOutsideAllowlist(t, jcsTransformCall, jcsAllowlist,
		"canonicalizes with gowebpki/jcs directly — sign/verify through the SDK faces (the JCS switch is SDK-internal)")
}

// TestForbiddenPathsStayDeleted fails when a deleted disease home reappears.
func TestForbiddenPathsStayDeleted(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	for _, rel := range forbiddenPaths {
		if _, err := os.Stat(filepath.Join(root, rel)); err == nil {
			t.Errorf("%s exists again — its logic moved into the RAMP SDK "+
				"(sdk/go/connectserver, sdk/go/core, sdk/go/helpers); do not resurrect the app copy", rel)
		}
	}
}

// --- meta-tests: prove the detectors themselves work -----------------------

// TestMeta_EmitUnpopulatedDetectorCatchesAliasedMultilineLiteral is the
// positive + regex-slip meta-test: an aliased protojson import with a
// multi-line MarshalOptions literal must still match (the detector is
// content-anchored, not alias- or single-line-anchored).
func TestMeta_EmitUnpopulatedDetectorCatchesAliasedMultilineLiteral(t *testing.T) {
	t.Parallel()
	slip := "return pj.MarshalOptions{\n\tAllowPartial:    true,\n\tEmitUnpopulated: true,\n}.Marshal(pm)"
	if !emitUnpopulatedLiteral.MatchString(slip) {
		t.Fatal("detector missed the aliased multi-line EmitUnpopulated literal — regex-slip regression")
	}
}

// TestMeta_EmitUnpopulatedDetectorPassesSDKCall is the negative meta-test: the
// sanctioned SDK constructor call must NOT match.
func TestMeta_EmitUnpopulatedDetectorPassesSDKCall(t *testing.T) {
	t.Parallel()
	clean := "codecOpt := connectrpc.WithCodec(connectserver.EmitUnpopulatedJSONCodec())"
	if emitUnpopulatedLiteral.MatchString(clean) {
		t.Fatal("detector wrongly flagged the sanctioned SDK constructor call")
	}
}

// TestMeta_SignHelperDetectorCatchesDirectCall is the positive meta-test for
// the signing detector.
func TestMeta_SignHelperDetectorCatchesDirectCall(t *testing.T) {
	t.Parallel()
	dirty := "if err := helpers.AppendSignature(ctx, req, body, s, opts); err != nil {"
	if !signHelperCall.MatchString(dirty) {
		t.Fatal("detector missed a direct helpers.AppendSignature call")
	}
	clean := "t, err := signingtransport.New(inner, dir, priv, window)"
	if signHelperCall.MatchString(clean) {
		t.Fatal("detector wrongly flagged a canonical-transport composition")
	}
}

// --- meta-tests for ed25519.Sign guard (TestNoHandRolledEd25519Sign) ---------
// These exercise the ed25519.Sign detector (ed25519SignCall / ed25519SignAllowlist)
// that TestNoHandRolledEd25519Sign uses to keep raw ed25519.Sign( calls out of the
// production tree: one positive case (a raw call is flagged) and one negative.

// TestMeta_Ed25519SignDetectorFlagsRawCall is the positive meta-test:
// a source snippet containing ed25519.Sign( must be detected.
func TestMeta_Ed25519SignDetectorFlagsRawCall(t *testing.T) {
	t.Parallel()
	slip := `sig := ed25519.Sign(privKey, []byte(payload))`
	if !ed25519SignCall.MatchString(slip) {
		t.Fatal("ed25519SignCall detector missed a direct ed25519.Sign( call")
	}
}

// TestMeta_Ed25519SignDetectorPassesAllowlistedFile ensures that the
// allowlisted path (cosign.go) is exempted from the guard. Meta-test
// confirms the allowlist map contains exactly that path.
func TestMeta_Ed25519SignDetectorPassesAllowlistedFile(t *testing.T) {
	t.Parallel()
	if !ed25519SignAllowlist["src/broker/internal/signing/cosign.go"] {
		t.Fatal("ed25519SignAllowlist must contain src/broker/internal/signing/cosign.go")
	}
}

// TestMeta_Ed25519SignDetectorPassesCleanSource is the negative meta-test:
// source that uses the SDK signing transport must NOT match.
func TestMeta_Ed25519SignDetectorPassesCleanSource(t *testing.T) {
	t.Parallel()
	clean := `transport := core.NewSigningTransport(inner, privSeed, keyid, ttl)`
	if ed25519SignCall.MatchString(clean) {
		t.Fatal("ed25519SignCall detector wrongly flagged SDK signing-transport call")
	}
}

// --- meta-tests for jcs.Transform guard (TestNoHandRolledJCSCanonicalization) ------
// These tests reference jcsTransformCall which does NOT exist yet. Same compile-
// failure red as the ed25519 guard above.

// TestMeta_JCSTransformDetectorFlagsDirectCall is the positive meta-test:
// a source snippet containing jcs.Transform( must be detected.
func TestMeta_JCSTransformDetectorFlagsDirectCall(t *testing.T) {
	t.Parallel()
	slip := `canon, err := jcs.Transform(pj)`
	if !jcsTransformCall.MatchString(slip) {
		t.Fatal("jcsTransformCall detector missed a direct jcs.Transform( call")
	}
}

// TestMeta_JCSTransformDetectorPassesSDKUsage is the negative meta-test:
// a comment mentioning jcs internally (the SDK wraps this) must NOT match,
// and a call to the SDK helper must NOT match.
func TestMeta_JCSTransformDetectorPassesSDKUsage(t *testing.T) {
	t.Parallel()
	// Comment only — not a call site.
	comment := `// sdk uses jcs internally via helpers.SignOffer`
	if jcsTransformCall.MatchString(comment) {
		t.Fatal("jcsTransformCall detector wrongly flagged a comment")
	}
	// SDK helper call — no jcs.Transform at the call site.
	sdkCall := `signed, err := helpers.SignOffer(ctx, offer, privKey)`
	if jcsTransformCall.MatchString(sdkCall) {
		t.Fatal("jcsTransformCall detector wrongly flagged an SDK helper call")
	}
}
