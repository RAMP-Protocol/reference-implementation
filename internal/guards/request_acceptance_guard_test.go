package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func requestProofPrecedesClaim(src []byte) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "exchange_batch_replay.go", src, 0)
	if err != nil {
		return false
	}
	var verify, claim token.Pos
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "admitBatchRequest" {
			continue
		}
		ast.Inspect(fn, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case "verifyRequestAcceptance":
				verify = call.Pos()
			case "ClaimRequest":
				claim = call.Pos()
			}
			return true
		})
	}
	return verify.IsValid() && claim.IsValid() && verify < claim
}

func TestRequestAcceptanceGuardsRequestClaim(t *testing.T) {
	t.Parallel()
	root := repoRoot(t)
	admission, err := os.ReadFile(filepath.Join(root, "src/exchange/internal/service/exchange_batch_replay.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !requestProofPrecedesClaim(admission) {
		t.Fatal("admitBatchRequest must verify the complete request proof before ClaimRequest")
	}
	verifier, err := os.ReadFile(filepath.Join(root, "src/exchange/internal/service/agent_acceptance.go"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(verifier), "helpers.VerifyRequestAcceptanceProjection(") {
		t.Fatal("request proof verification must require the complete per-Exchange projection")
	}
}

func TestMeta_RequestProofOrderDetector(t *testing.T) {
	t.Parallel()
	clean := []byte(`package p
func (s *S) admitBatchRequest() { s.verifyRequestAcceptance(); s.transactions.ClaimRequest() }`)
	dirty := []byte(`package p
func (s *S) admitBatchRequest() { s.transactions.ClaimRequest(); s.verifyRequestAcceptance() }`)
	if !requestProofPrecedesClaim(clean) {
		t.Fatal("detector rejected verification before claim")
	}
	if requestProofPrecedesClaim(dirty) {
		t.Fatal("detector missed claim before verification")
	}
}
