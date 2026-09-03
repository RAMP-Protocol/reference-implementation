package guards

import (
	"go/ast"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// One ExecuteTransaction verifies every signature against ONE registered-agent
// key snapshot. The rule is enforced by shape rather than by discipline: the two
// acceptance verifiers take the resolved key and take no context.Context, and
// every repository read in this codebase requires a context. A verifier that
// cannot reach the registry cannot verify a later item against a key that
// arrived after the request started.
//
// Without that shape a key rotation landing mid-request verifies the complete
// request proof and the early items against the old key and the later items
// against the new one. The mixed response is then finalized onto the request
// claim write-once, so every later retry under that idempotency key replays the
// stale SIGNATURE_INVALID denials — a permanent wrong answer built out of a
// momentary inconsistency.

// verifierPath is the file both verifiers are defined in.
const verifierPath = "src/exchange/internal/service/agent_acceptance.go"

// takesKeyWithoutContext reports whether the named function in src is shaped so
// it cannot re-read the agent registry: it accepts the resolved agentKey
// snapshot, and it accepts no context.Context.
func takesKeyWithoutContext(src []byte, name string) bool {
	f, err := parser.ParseFile(token.NewFileSet(), "agent_acceptance.go", src, 0)
	if err != nil {
		return false
	}
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != name {
			continue
		}
		takesKey := false
		for _, param := range fn.Type.Params.List {
			switch types.ExprString(param.Type) {
			case "context.Context":
				return false
			case "agentKey":
				takesKey = true
			}
		}
		return takesKey
	}
	return false
}

func TestAcceptanceVerifiersCannotReloadTheAgentKey(t *testing.T) {
	t.Parallel()
	src, err := os.ReadFile(filepath.Join(repoRoot(t), verifierPath))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"verifyAgentAcceptance", "verifyRequestAcceptance"} {
		if !takesKeyWithoutContext(src, name) {
			t.Errorf("%s must take the resolved agentKey snapshot and no context.Context, "+
				"so no call site can re-read the agent registry mid-request", name)
		}
	}
	// The same rule from the other side: nothing in this file reaches the agents
	// repository at all, so the key can only have come from the one resolution
	// the request already did.
	if strings.Contains(string(src), "s.agents") {
		t.Errorf("%s reads the agents repository; the request's key snapshot is resolved "+
			"once by resolveAgent and passed in", verifierPath)
	}
}

func TestMeta_KeySnapshotDetector(t *testing.T) {
	t.Parallel()
	clean := []byte(`package p
func verifyAgentAcceptance(req *R, key agentKey) (agentBinding, error) { return agentBinding{}, nil }`)
	withContext := []byte(`package p
func verifyAgentAcceptance(ctx context.Context, req *R, key agentKey) (agentBinding, error) { return agentBinding{}, nil }`)
	withAgentID := []byte(`package p
func verifyAgentAcceptance(req *R, agentID string) (agentBinding, error) { return agentBinding{}, nil }`)

	if !takesKeyWithoutContext(clean, "verifyAgentAcceptance") {
		t.Error("detector rejected a verifier that takes the key and no context")
	}
	if takesKeyWithoutContext(withContext, "verifyAgentAcceptance") {
		t.Error("detector missed a verifier that can reach the registry through a context")
	}
	if takesKeyWithoutContext(withAgentID, "verifyAgentAcceptance") {
		t.Error("detector missed a verifier that takes an agent id instead of the key")
	}
	if takesKeyWithoutContext(clean, "someOtherName") {
		t.Error("detector reported a function that is not defined at all")
	}
}
