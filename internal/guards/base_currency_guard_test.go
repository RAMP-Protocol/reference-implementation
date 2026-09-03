// The Exchange's advertised base_currency must be the currency it actually
// prices in, and only source can see whether it is.
//
// The protocol makes base_currency a statement to other parties, not a label:
// it declares that every unit_cost from this Exchange is denominated in that
// currency, and normalized_cost — the field the spec calls the universal
// comparison metric — is defined as denominated in it. An agent comparing
// offers across exchanges reads our prices through it. Advertise USD while the
// ledger charges EUR and every one of those numbers is wrong by the exchange
// rate, with nothing in this repository noticing: nothing here READS
// base_currency, so no round-trip assertion can catch it. The document is
// write-only from our side and load-bearing from theirs.
//
// That is exactly what shipped. The value was a "USD" literal in the
// composition root while the deployed ledger ran on EUR, and every test passed
// throughout, because each one supplies its own well-known config and asserts
// the value it just supplied.
//
// So the check is structural: a well-known config built in app code must take
// its base currency from an expression — the selected billing backend's ledger
// currency — never from a literal or a string constant. A literal is a second
// source of truth for a fact the billing adapter already owns, and the two
// drifted the moment a deployment changed currency.
//
// Test files are out of scope on purpose. A test that builds a manifest to
// assert on it must be free to write the currency it means, and the walker used
// here parses app sources only.
package guards

import (
	"go/ast"
	"go/token"
	"testing"
)

// baseCurrencyField is the config field every well-known builder in this repo
// sets to declare its pricing denomination.
const baseCurrencyField = "BaseCurrency"

// literalBaseCurrency reports the hardcoded value a composite literal assigns to
// BaseCurrency, and whether it found one. A value written through a string
// constant declared in the same file resolves the same as the literal: naming
// it does not make it derived.
func literalBaseCurrency(kv *ast.KeyValueExpr, consts map[string]string) (string, bool) {
	key, ok := kv.Key.(*ast.Ident)
	if !ok || key.Name != baseCurrencyField {
		return "", false
	}
	if v, isLit := stringValue(kv.Value); isLit {
		return v, true
	}
	if ident, isIdent := kv.Value.(*ast.Ident); isIdent {
		if v, declared := consts[ident.Name]; declared {
			return v, true
		}
	}
	return "", false
}

// TestBaseCurrencyIsNeverHardcoded fails when app code stamps a well-known
// document's base currency from a literal instead of the ledger's own currency.
func TestBaseCurrencyIsNeverHardcoded(t *testing.T) {
	t.Parallel()
	forEachAppFile(t, func(rel string, f *ast.File) {
		consts := stringConstsIn(f)
		ast.Inspect(f, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok {
				return true
			}
			for _, elt := range lit.Elts {
				kv, isKV := elt.(*ast.KeyValueExpr)
				if !isKV {
					continue
				}
				if value, hardcoded := literalBaseCurrency(kv, consts); hardcoded {
					t.Errorf(
						"%s: %s is set to the hardcoded %q. It must come from the "+
							"selected billing backend's ledger currency, so the currency "+
							"this Exchange advertises cannot disagree with the currency it "+
							"charges in.",
						rel, baseCurrencyField, value,
					)
				}
			}
			return true
		})
	})
}

// TestMeta_BaseCurrencyDetectorFlagsALiteral proves the check above fires. A
// guard that has never been seen failing is a guard that might be reading
// nothing at all.
func TestMeta_BaseCurrencyDetectorFlagsALiteral(t *testing.T) {
	t.Parallel()
	kv := &ast.KeyValueExpr{
		Key:   &ast.Ident{Name: baseCurrencyField},
		Value: &ast.BasicLit{Kind: token.STRING, Value: `"USD"`},
	}
	got, hardcoded := literalBaseCurrency(kv, map[string]string{})
	if !hardcoded || got != "USD" {
		t.Errorf("detector missed a literal: got %q, hardcoded=%v", got, hardcoded)
	}
}

// TestMeta_BaseCurrencyDetectorFlagsANamedConstant proves naming the literal
// does not hide it. This is the shape a fix under review time pressure takes:
// move "USD" into a const, keep stamping it, and the diff looks derived.
func TestMeta_BaseCurrencyDetectorFlagsANamedConstant(t *testing.T) {
	t.Parallel()
	kv := &ast.KeyValueExpr{
		Key:   &ast.Ident{Name: baseCurrencyField},
		Value: &ast.Ident{Name: "defaultCurrency"},
	}
	got, hardcoded := literalBaseCurrency(kv, map[string]string{"defaultCurrency": "USD"})
	if !hardcoded || got != "USD" {
		t.Errorf("detector missed a named constant: got %q, hardcoded=%v", got, hardcoded)
	}
}

// TestMeta_BaseCurrencyDetectorPassesADerivedValue proves the check accepts the
// correct shape, so it cannot pass by rejecting everything.
func TestMeta_BaseCurrencyDetectorPassesADerivedValue(t *testing.T) {
	t.Parallel()
	kv := &ast.KeyValueExpr{
		Key:   &ast.Ident{Name: baseCurrencyField},
		Value: &ast.SelectorExpr{X: &ast.Ident{Name: "d"}, Sel: &ast.Ident{Name: "ledgerCurrency"}},
	}
	if _, hardcoded := literalBaseCurrency(kv, map[string]string{}); hardcoded {
		t.Error("detector flagged a derived value; it must accept d.ledgerCurrency")
	}
}
