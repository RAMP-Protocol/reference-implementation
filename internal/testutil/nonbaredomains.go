package testutil

// The one table of values helpers.IsBareDomain refuses.
//
// Three places drive this rule and each had grown its own list: the two account
// tools' argument check, the usage report's, and the allowlist parser that must
// admit exactly what the tools will accept. The lists had already diverged —
// one carried a fragment case the others did not, another carried a leading
// underscore label, and a third carried a bracketed IPv6 literal — so a change
// that started admitting one of those would have been caught by one list and
// passed by two.
//
// The shapes matter beyond the values. Five entries separate the rule these
// checks actually apply, helpers.IsBareDomain, from the weaker question of
// whether a value merely parses as a host, helpers.IsBareHost: port zero, the
// underscored container alias, the leading underscore label, and the two
// bracketed IPv6 forms. IsBareHost accepts all five. Every other entry is
// refused by both rules, so without these five the narrow rule could be swapped
// for the weak one and nothing would notice — and the weak one admits values the
// wire then refuses at the far end.
//
// A sixth separates conditionally: a trailing root dot on a host carrying no
// port ("exchange.example.") is a usable host, while the same dot after a port
// ("127.0.0.1:8081.") is not. So a suite whose fixture serves a mapped loopback
// port gets five separators and one whose peer has a real name gets six. That is
// why the count is written out here rather than asserted per suite.

// NonBareDomain is one way an exchange argument can fail the wire's own shape
// rule, rendered against a host that would otherwise have answered.
type NonBareDomain struct {
	// Name says which shape this is, for the subtest.
	Name string
	// Of renders the case. Most entries decorate the given host, so the value
	// names a host a test's own fixture is really serving and a refusal cannot
	// be mistaken for "nothing was listening". The entries that carry their own
	// port or their own literal syntax ignore it — appending a port to a host
	// that already has one would test a different malformation than the name
	// claims.
	Of func(host string) string
}

// NonBareDomains is the shared table. It deliberately excludes the empty string:
// an absent exchange is a MISSING argument, which each surface answers in its
// own way — a schema refusal on one tool, the note-backed mode on another — and
// none of those is this rule.
var NonBareDomains = []NonBareDomain{
	{"scheme", func(h string) string { return "http://" + h }},
	{"path", func(h string) string { return h + "/register" }},
	{"query", func(h string) string { return h + "?token=x" }},
	{"fragment", func(h string) string { return h + "#frag" }},
	{"bare fragment truncates to the root", func(h string) string { return h + "#" }},
	{"path and query behind a fragment", func(h string) string { return h + "/internal/admin?token=x#" }},
	{"userinfo before the host", func(h string) string { return "user@" + h }},
	{"userinfo names a different host", func(h string) string { return h + "@internal.invalid" }},
	{"trailing root dot", func(h string) string { return h + "." }},
	// Host-independent from here down: each carries its own port or its own
	// literal syntax, so decorating a caller's host would change what is tested.
	{"port zero", func(string) string { return "exchange.example:0" }},
	{"empty port", func(string) string { return "exchange.example:" }},
	{"underscored container alias", func(string) string { return "ex_change.internal" }},
	{"leading underscore label", func(string) string { return "_exchange.example" }},
	{"bracketed IPv6 literal", func(string) string { return "[2001:db8::1]" }},
	{"bracketed IPv6 loopback with a port", func(string) string { return "[::1]:8081" }},
}
