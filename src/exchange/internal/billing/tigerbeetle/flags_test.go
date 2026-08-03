package tigerbeetle

import "testing"

// TestDefaultFlagsForCode pins the folded policy: agent accounts are debit-capped
// (no override needed at the call site), owner/platform accounts keep history and
// are not capped. If a future edit drops the agent cap from DefaultFlagsForCode,
// this fails rather than silently letting an agent overdraw.
func TestDefaultFlagsForCode(t *testing.T) {
	agent := DefaultFlagsForCode(CodeAgent)
	if !agent.DebitsMustNotExceedCredits {
		t.Error("agent account must be debit-capped (DebitsMustNotExceedCredits)")
	}
	if agent.History {
		t.Error("agent account should not carry history in v1")
	}
	for _, code := range []AccountCode{CodeOwner, CodePlatform} {
		f := DefaultFlagsForCode(code)
		if !f.History {
			t.Errorf("code %d: History must be enabled for reporting reads", code)
		}
		if f.DebitsMustNotExceedCredits {
			t.Errorf("code %d: owner/platform accounts must not be debit-capped", code)
		}
	}
}
