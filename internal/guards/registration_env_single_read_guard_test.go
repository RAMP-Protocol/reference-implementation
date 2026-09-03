// Structural guard: each environment variable that carries the Exchange's
// registration configuration is read in exactly one place.
//
// The compile-once rules for the schema DOCUMENT are the sibling file,
// regschema_single_load_guard_test.go, whose header explains why a second value
// is the failure worth preventing. This file covers the route those rules share
// with the terms digest: the environment read that produces the value in the
// first place.
//
// The digest has no Load call to watch. It is configuration rather than a
// compiled document, so the environment read IS its only route to a second
// value — and it needs the guard for exactly the reason the schema does. The
// manifest publishes the digest as terms_digest and the Register gate refuses a
// registration naming a different revision, so an Exchange advertising one
// revision while checking against another is wrong in a way neither reader can
// detect from where it stands.
//
// Every detector and rule meta-test below runs over BOTH variables from one
// table. A second variable carrying fewer meta-tests than the one beside it is a
// weaker guard wearing the same name, and two copied sets are free to drift
// apart — which is the failure this guard exists to catch one level up.

package guards

import (
	"go/ast"
	"testing"
)

// The two variables the composition root reads. Written out here rather than
// shared with production code on purpose: a guard that imported the constants it
// checks would follow a rename instead of reporting one.
const (
	registrationSchemaEnvVar = "EXCHANGE_REGISTRATION_SCHEMA"
	termsDigestEnvVar        = "EXCHANGE_TERMS_DIGEST"
)

// registrationEnvVars is what the one-place rule and every environment
// meta-test run over. Both variables are sanctioned in the same file, because
// both are read by the same loader and handed to the same two readers.
//
// A table rather than a second copy of each test. The schema route had five
// meta-tests behind it; adding the digest as a copied set would have doubled
// them and let the two variables' coverage drift apart, which is the same
// failure shape this guard exists to catch one level up.
var registrationEnvVars = []struct {
	name    string
	envVar  string
	allowed string
}{
	{"the registration schema", registrationSchemaEnvVar, regschemaLoadRoot},
	{"the terms digest", termsDigestEnvVar, regschemaLoadRoot},
}

// countEnvReads counts the CALLS in f that pass envVar as an argument, written
// either as a literal in either quoting form or as a constant declared in the
// same file.
//
// Counting calls rather than literals is what makes the answer the number of
// READS. A file that names the variable only inside a longer message counts
// none, which is the composition root's own error text; a file that holds the
// name in one constant and reads it three times counts three.
func countEnvReads(f *ast.File, envVar string) int {
	consts := stringConstsIn(f)
	count := 0
	ast.Inspect(f, func(n ast.Node) bool {
		call, isCall := n.(*ast.CallExpr)
		if !isCall {
			return true
		}
		for _, arg := range call.Args {
			v, isString := stringValue(arg)
			if !isString {
				if id, isIdent := arg.(*ast.Ident); isIdent {
					v = consts[id.Name]
				}
			}
			if v == envVar {
				count++
				return true
			}
		}
		return true
	})
	return count
}

// TestRegistrationEnvVarsReadOnce fails when either configured registration
// variable is named outside the composition root, or more than once inside it.
// This is the route the load-once rule is really about: two readers agree for as
// long as both take the same value, and diverge silently the day one of them
// gains a second source — a file, a database row, a per-tenant default.
func TestRegistrationEnvVarsReadOnce(t *testing.T) {
	t.Parallel()
	for _, v := range registrationEnvVars {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			forEachAppFile(t, func(rel string, f *ast.File) {
				n := countEnvReads(f, v.envVar)
				if !countIsWrong(rel, v.allowed, n) {
					return
				}
				if rel == v.allowed {
					t.Errorf("%s reads %s %d times, want exactly 1 — it is read once, and the single value reaches both readers. Zero reads fails here too: a rename would otherwise leave this guard green with nothing left to guard.", rel, v.envVar, n)
					return
				}
				t.Errorf("%s reads %s — the variable is read once, at %s. Take the loaded registrationConfig instead.", rel, v.envVar, v.allowed)
			})
		})
	}
}

// TestMeta_EnvDetectorCatchesASecondRead is the positive meta-test for the
// environment detector.
func TestMeta_EnvDetectorCatchesASecondRead(t *testing.T) {
	t.Parallel()
	for _, v := range registrationEnvVars {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			f := parseSnippet(t, "package x\n\nfunc gate() string { return runhttp.EnvOr(\""+v.envVar+"\", \"\") }\n")
			if got := countEnvReads(f, v.envVar); got != 1 {
				t.Fatalf("detector counted %d reads of %s, want 1", got, v.envVar)
			}
		})
	}
}

// TestMeta_EnvDetectorCatchesABackquotedRead drives the quoting form a
// double-quoted comparison cannot see. Go accepts a raw string literal
// anywhere an interpreted one goes, and go/ast keeps the backquotes in the
// node's value, so this is a working second read that a text match reports as
// a clean tree.
func TestMeta_EnvDetectorCatchesABackquotedRead(t *testing.T) {
	t.Parallel()
	for _, v := range registrationEnvVars {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			f := parseSnippet(t, "package x\n\nfunc gate() string { return runhttp.EnvOr(`"+v.envVar+"`, \"\") }\n")
			if got := countEnvReads(f, v.envVar); got != 1 {
				t.Fatalf("detector counted %d backquoted reads of %s, want 1", got, v.envVar)
			}
		})
	}
}

// TestMeta_EnvDetectorCatchesReadsThroughAConstant drives the other form a
// literal count answers wrongly. The name appears once in the source and is
// read from two places, which is exactly the divergence this guard is about:
// two compiles, two sources, one spelling.
func TestMeta_EnvDetectorCatchesReadsThroughAConstant(t *testing.T) {
	t.Parallel()
	for _, v := range registrationEnvVars {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			f := parseSnippet(t, "package x\n\nconst envName = \""+v.envVar+"\"\n\n"+
				"func gate() string { return runhttp.EnvOr(envName, \"\") }\n"+
				"func other() string { return os.Getenv(envName) }\n")
			if got := countEnvReads(f, v.envVar); got != 2 {
				t.Fatalf("detector counted %d reads through a constant, want 2 — one spelling, two reads", got)
			}
		})
	}
}

// TestMeta_OnePlaceRuleRejectsZeroUses drives the rule rather than the
// detector, through the count no passing tree can produce. A sanctioned file
// holding no uses at all is the state a rename or a deleted load leaves behind,
// and it must fail rather than read as "exactly one".
func TestMeta_OnePlaceRuleRejectsZeroUses(t *testing.T) {
	t.Parallel()
	for _, v := range registrationEnvVars {
		for _, tc := range []struct {
			name string
			rel  string
			n    int
			want bool
		}{
			{"the sanctioned file with none", v.allowed, 0, true},
			{"the sanctioned file with one", v.allowed, 1, false},
			{"the sanctioned file with two", v.allowed, 2, true},
			{"another file with none", "src/exchange/cmd/server/main.go", 0, false},
			{"another file with one", "src/exchange/cmd/server/main.go", 1, true},
		} {
			t.Run(v.name+"/"+tc.name, func(t *testing.T) {
				t.Parallel()
				if got := countIsWrong(tc.rel, v.allowed, tc.n); got != tc.want {
					t.Errorf("countIsWrong(%q, %d) = %v, want %v", tc.rel, tc.n, got, tc.want)
				}
			})
		}
	}
}

// TestMeta_EnvDetectorPassesAMessageMentioningTheVariable is the negative
// meta-test: the composition root names the variable in the error it returns,
// and an error message is not a second read.
func TestMeta_EnvDetectorPassesAMessageMentioningTheVariable(t *testing.T) {
	t.Parallel()
	for _, v := range registrationEnvVars {
		t.Run(v.name, func(t *testing.T) {
			t.Parallel()
			f := parseSnippet(t, "package x\n\nfunc fail(err error) error "+
				"{ return fmt.Errorf(\"registration: invalid "+v.envVar+": %w\", err) }\n")
			if got := countEnvReads(f, v.envVar); got != 0 {
				t.Fatalf("detector counted %d reads where the variable is only mentioned in a message, want 0", got)
			}
		})
	}
}
