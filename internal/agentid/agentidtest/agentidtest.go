// Package agentidtest publishes the corpus of values that name no directory
// host, so every layer that refuses them refuses the same set.
//
// Four suites hand-wrote their own list — the package that owns the rule, the
// repository, the registry and the register handler — and they had already
// drifted apart. Between them they covered ten values and no single list held
// more than six, with the owning package's list the weakest of the four: it
// tested neither an empty authority, nor an undialable port, nor a
// non-canonical dotted quad. A change to FromDirectory could therefore keep its
// own tests green and surface two layers down, in a suite that knows nothing
// about the rule.
//
// It is a separate package rather than an export from agentid so the corpus does
// not travel in a production binary — the convention httptest and iotest follow.
package agentidtest

// NonHostValue is one corpus entry: the value, and a name explaining why it names
// no host. The name is what a t.Run subtest is called, so a failure reads as the
// rule that was broken rather than as an opaque string.
type NonHostValue struct {
	Name  string
	Value string
}

// NonHostValues returns every value that is present but names no host.
//
// Deliberately EXCLUDES the empty string and whitespace. Those are a different
// class — "the field is missing" rather than "the field is malformed" — and the
// layers answer them differently on purpose: the register handler replies
// "agent_id required" before it ever asks whether the value is a host. Folding
// them in would force each caller to special-case them and the corpus would stop
// meaning one thing. Each layer keeps its own missing-value test.
//
// The returned slice is fresh on every call, so a caller may sort or filter it
// without disturbing another test.
func NonHostValues() []NonHostValue {
	return []NonHostValue{
		{
			Name:  "sf-dictionary form",
			Value: `agent2="https://agent.example"`,
		},
		{
			Name:  "inline data: directory",
			Value: `data:application/http-message-signatures-directory;utf8,{"keys":[]}`,
		},
		{
			Name:  "quoted value never unwrapped",
			Value: `"https://agent.example"`,
		},
		{
			Name:  "scheme with no host",
			Value: "https://",
		},
		{
			Name:  "authority that parses empty",
			Value: "//agent.example",
		},
		{
			Name:  "port nothing can dial",
			Value: "https://agent.example:0",
		},
		{
			Name:  "port out of range",
			Value: "https://agent.example:65536",
		},
		{
			Name:  "non-canonical dotted quad",
			Value: "010.0.0.1",
		},
	}
}
