package agentid_test

// Unit tests: FromDirectory is a parser over the Signature-Agent directory value,
// which the testing doctrine admits as a unit-test category. What it decides is
// not cosmetic — the result is the agents-table primary key and the host an
// outbound directory fetch is aimed at.

import (
	"net/http"
	"strings"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/agentid/agentidtest"
)

// TestDirectoryFromHeader_acceptedForms pins the two Signature-Agent wire forms.
// The quoted one is what Web Bot Auth defines the value to be — quoting is not
// optional in structured fields — and reading it verbatim carried the quotes into
// the directory URI, where no host could be found and the request was refused.
func TestDirectoryFromHeader_acceptedForms(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
		want   string
	}{
		{"quoted sf-string (conformant)", `"https://agent.example"`, "https://agent.example"},
		{"bare token (RAMP's own)", "https://agent.example", "https://agent.example"},
		{"quoted bare host", `"agent.example"`, "agent.example"},
		{"bare host:port", "identity:8080", "identity:8080"},
		{"surrounding whitespace", `  "https://agent.example"  `, "https://agent.example"},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentid.DirectoryFromHeader(tc.header); got != tc.want {
				t.Errorf("DirectoryFromHeader(%q) = %q; want %q", tc.header, got, tc.want)
			}
		})
	}
}

// TestDirectoryFromHeader_unsupportedFormsNotUnwrapped pins the refusals as
// deliberate. Unwrapping the sf-dictionary form would also admit its data: member,
// which inlines a whole key directory into the header — and key resolution rests on
// FETCHING the directory from a location the signer had to control. These values
// pass through unchanged and die at FromDirectory, which finds no host in them.
func TestDirectoryFromHeader_unsupportedFormsNotUnwrapped(t *testing.T) {
	for _, tc := range []struct {
		name   string
		header string
	}{
		{"sf-dictionary", `agent2="https://agent.example"`},
		{"inline data: directory", `data:application/http-message-signatures-directory;utf8,{"keys":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := agentid.DirectoryFromHeader(tc.header); got != tc.header {
				t.Errorf("DirectoryFromHeader(%q) = %q; want it passed through unchanged", tc.header, got)
			}
			if _, err := agentid.FromDirectory(tc.header); err == nil {
				t.Errorf("FromDirectory(%q) accepted an unsupported form as an identity", tc.header)
			}
		})
	}
}

// TestDirectoryFromHeader_thenFromDirectory covers the two steps as the pipeline
// they are: whatever form the header arrived in, the identity that comes out is the
// same host. This is the property every caller downstream depends on.
func TestDirectoryFromHeader_thenFromDirectory(t *testing.T) {
	for _, header := range []string{
		`"https://agent.example"`,
		"https://agent.example",
		`"http://agent.example"`,
		"agent.example",
		`"agent.example"`,
	} {
		got, err := agentid.FromDirectory(agentid.DirectoryFromHeader(header))
		if err != nil {
			t.Fatalf("header %q: %v", header, err)
		}
		if got != "agent.example" {
			t.Errorf("header %q resolved to identity %q; want %q", header, got, "agent.example")
		}
	}
}

// TestFromDirectory_collapsesSpellings is the property the ticket asks for: one
// host is one agent, however the caller spelled it. The scheme was the axis the
// ticket named, but it is only one of several, and closing it alone left the bug
// reachable by changing a single letter's case — DNS is case-insensitive, the root
// dot is optional, and :443 is what "https" already means. Each spelling below
// fetches the same directory and presents the same key, so each must resolve to
// the same identity rather than to its own row, key pin and billing ref.
func TestFromDirectory_collapsesSpellings(t *testing.T) {
	for _, tc := range []struct {
		axis string
		ref  string
	}{
		{"scheme (https)", "https://agent.example"},
		{"scheme (http)", "http://agent.example"},
		{"no scheme", "agent.example"},
		{"case, mixed", "https://Agent.Example"},
		{"case, upper and no scheme", "AGENT.EXAMPLE"},
		{"trailing root dot", "https://agent.example."},
		{"case and root dot together", "HTTPS://Agent.Example."},
		{"https default port", "https://agent.example:443"},
		{"http default port", "http://agent.example:80"},
		{"default port, no scheme", "agent.example:443"},
		{"zero-padded https default port", "https://agent.example:0443"},
		{"zero-padded http default port", "http://agent.example:080"},
		{"double-padded default port", "https://agent.example:00443"},
		{"padded default port, no scheme", "agent.example:0443"},
		{"trailing slash", "https://agent.example/"},
	} {
		t.Run(tc.axis, func(t *testing.T) {
			got, err := agentid.FromDirectory(tc.ref)
			if err != nil {
				t.Fatalf("FromDirectory(%q): %v", tc.ref, err)
			}
			if got != "agent.example" {
				t.Errorf("FromDirectory(%q) = %q; want %q — this spelling is a second identity for one agent",
					tc.ref, got, "agent.example")
			}
		})
	}
}

// TestFromDirectory_foldsToALabel pins the IDN axis. A Unicode name and its
// punycode encoding are the same name to DNS, so they must be the same agent. The
// A-label form is the canonical one because it is what actually gets resolved.
func TestFromDirectory_foldsToALabel(t *testing.T) {
	const want = "xn--e1afmkfd.xn--p1ai"
	for _, ref := range []string{"https://пример.рф", "ПРИМЕР.РФ", want, "https://" + want} {
		t.Run(ref, func(t *testing.T) {
			got, err := agentid.FromDirectory(ref)
			if err != nil {
				t.Fatalf("FromDirectory(%q): %v", ref, err)
			}
			if got != want {
				t.Errorf("FromDirectory(%q) = %q; want %q", ref, got, want)
			}
		})
	}
}

// TestFromDirectory_keepsNonDefaultPort pins that a real port survives, in ONE
// spelling. A compose stack serves several agents on one host at different ports,
// so folding those away would collapse DISTINCT agents into one identity — the
// opposite of the bug being fixed. Only :80 and :443 are dropped, and only
// because they are exactly what the two deployment schemes already imply.
//
// The padded forms are here because keeping a port is not the same as keeping the
// caller's spelling of it. ":08080" dials the same TCP port as ":8080", so the two
// must be one identity; folding only the defaults would have left every
// non-default port splittable by a leading zero.
func TestFromDirectory_keepsNonDefaultPort(t *testing.T) {
	for _, ref := range []string{
		"http://identity:8080", "https://identity:8080", "identity:8080", "IDENTITY:8080",
		"https://identity:08080", "identity:008080", "IDENTITY:08080",
	} {
		t.Run(ref, func(t *testing.T) {
			got, err := agentid.FromDirectory(ref)
			if err != nil {
				t.Fatalf("FromDirectory(%q): %v", ref, err)
			}
			if got != "identity:8080" {
				t.Errorf("FromDirectory(%q) = %q; want %q", ref, got, "identity:8080")
			}
		})
	}
}

// TestFromDirectory_collapsesIPLiteralSpellings is the scheme/case/port property
// again, for the one kind of host DNS never sees. A compose or dev stack can name
// an agent by address, and an IPv6 address has many legal texts: zero-run
// compression, leading zeros in a group, and the IPv4-mapped forms are all the
// same 128 bits. No resolver stands between those spellings and the agents table,
// so nothing else would have collapsed them.
func TestFromDirectory_collapsesIPLiteralSpellings(t *testing.T) {
	for _, tc := range []struct {
		want string
		refs []string
	}{
		{"[::1]", []string{
			"https://[::1]",
			"[::1]",
			"https://[0:0:0:0:0:0:0:1]",
			"https://[::0001]",
			"https://[0000:0000:0000:0000:0000:0000:0000:0001]",
		}},
		{"[2001:db8::1]", []string{
			"https://[2001:DB8::1]",
			"https://[2001:db8:0:0:0:0:0:1]",
			"https://[2001:0db8::0001]",
			"[2001:DB8::1]:443", // the port https implies, folded as everywhere else
		}},
		{"[::ffff:127.0.0.1]", []string{
			"https://[::ffff:127.0.0.1]",
			"https://[::ffff:7f00:1]", // the same address, written as hex groups
		}},
		{"[::1]:8080", []string{
			"https://[::1]:8080",
			"http://[0:0:0:0:0:0:0:1]:08080", // both halves folded at once
		}},
	} {
		for _, ref := range tc.refs {
			t.Run(ref, func(t *testing.T) {
				got, err := agentid.FromDirectory(ref)
				if err != nil {
					t.Fatalf("FromDirectory(%q): %v", ref, err)
				}
				if got != tc.want {
					t.Errorf("FromDirectory(%q) = %q; want %q — this spelling is a second "+
						"identity for one address", ref, got, tc.want)
				}
			})
		}
	}
}

// TestFromDirectory_acceptsDottedQuad guards the fix below. A compose or dev stack
// really does name an agent by its IPv4 address, so the new numeric-label rule
// must leave every legal dotted-quad exactly where it was.
func TestFromDirectory_acceptsDottedQuad(t *testing.T) {
	for _, tc := range []struct{ ref, want string }{
		{"https://127.0.0.1", "127.0.0.1"},
		{"127.0.0.1", "127.0.0.1"},
		{"http://127.0.0.1:8080", "127.0.0.1:8080"},
		{"https://127.0.0.1:443", "127.0.0.1"},
		{"https://1.2.3.4", "1.2.3.4"},
		{"https://255.255.255.255", "255.255.255.255"},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			got, err := agentid.FromDirectory(tc.ref)
			if err != nil {
				t.Fatalf("FromDirectory(%q): %v", tc.ref, err)
			}
			if got != tc.want {
				t.Errorf("FromDirectory(%q) = %q; want %q", tc.ref, got, tc.want)
			}
		})
	}
}

// TestFromDirectory_rejectsAmbiguousOrUnresolvableDottedQuad is the padded-octet
// case, and it is REFUSED rather than folded — deliberately, and unlike every
// other axis in this file.
//
// "010.0.0.1" is 10.0.0.1 read as decimal and 8.0.0.1 read as octal, and the
// inet_aton family really does read it as octal. There is therefore no single
// address the padded text names, so folding it would mint an identity that
// denotes a different machine at dial time than it did when it was stored — a
// worse outcome than the duplicate row, because it is an authorization result
// that depends on whose parser runs. Refusing is the only answer that cannot be
// wrong.
//
// The rest end in a numeric label but are no address at all. They could never
// have resolved, so each could only ever have been a second identity for a host
// whose real directory lives elsewhere — the same reasoning that refuses a port
// outside 1-65535.
func TestFromDirectory_rejectsAmbiguousOrUnresolvableDottedQuad(t *testing.T) {
	for _, tc := range []struct {
		name string
		ref  string
	}{
		{"padded octet, decimal-or-octal", "https://010.0.0.1"},
		{"every octet padded", "https://127.000.000.001"},
		{"one padded octet", "https://127.0.0.01"},
		{"too many octets", "https://1.2.3.4.5"},
		{"octet out of range", "https://999.1.1.1"},
		{"bare numeric label", "https://12345"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := agentid.FromDirectory(tc.ref)
			if err == nil {
				t.Fatalf("FromDirectory(%q) = %q, nil; want a refusal — a name ending in a "+
					"numeric label can only be an IPv4 address, and this is not one", tc.ref, got)
			}
			if got != "" {
				t.Errorf("FromDirectory(%q) returned %q alongside its error; want empty", tc.ref, got)
			}
		})
	}
}

// TestFromDirectory_rejectsZonedIPLiteral pins the one IP literal that is refused
// rather than folded. A zone id names an interface on a particular machine, so the
// same text denotes different things on two hosts and denotes nothing once stored
// — it cannot be a shared identity. It is also the value FromDirectory was not
// idempotent for, since the zone's "%" arrives percent-encoded and a bare "%" is
// not legal in a URL authority on the way back in.
func TestFromDirectory_rejectsZonedIPLiteral(t *testing.T) {
	const ref = "https://[fe80::1%25eth0]"
	got, err := agentid.FromDirectory(ref)
	if err == nil {
		t.Fatalf("FromDirectory(%q) = %q, nil; want a refusal", ref, got)
	}
	if got != "" {
		t.Errorf("FromDirectory(%q) returned %q alongside its error; want empty", ref, got)
	}
}

// TestFromDirectory_rejectsUndialablePort covers the other half of parsing the
// port rather than comparing its text. A number outside 1-65535 cannot be dialed,
// so it cannot name a directory anyone can fetch — it can only be a second
// identity for a host whose real directory lives on a port that works. Refusing it
// keeps the agents table free of keys no fetch can ever follow.
func TestFromDirectory_rejectsUndialablePort(t *testing.T) {
	for _, ref := range []string{
		"https://agent.example:0",
		"https://agent.example:00",
		"https://agent.example:65536",
		"https://agent.example:99999",
		"https://agent.example:99999999999999999999", // more digits than an int holds
	} {
		t.Run(ref, func(t *testing.T) {
			got, err := agentid.FromDirectory(ref)
			if err == nil {
				t.Fatalf("FromDirectory(%q) = %q, nil; want an error — no such port can be dialed", ref, got)
			}
			if got != "" {
				t.Errorf("FromDirectory(%q) returned %q alongside its error; want empty", ref, got)
			}
		})
	}
}

// TestFromDirectory_distinctHostsStayDistinct is the guard on every folding above.
// Normalization is only safe while it still separates what identity has to
// separate; a fold that over-reached would silently merge two agents, which is a
// worse failure than the one being fixed because it is an authorization hole
// rather than an accounting one.
func TestFromDirectory_distinctHostsStayDistinct(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"agent.example", "other.example"},
		{"agent.example", "sub.agent.example"},
		{"agent.example", "agent.example:8080"},
		{"identity:8080", "identity:8081"},
		{"agent.example", "evil-agent.example"},
		{"[::1]", "[::2]"},
		{"[::1]", "[::1]:8080"},
		{"[2001:db8::1]", "[2001:db8::2]"},
		{"[::ffff:127.0.0.1]", "127.0.0.1"}, // an IPv4-mapped v6 address is not the v4 one
	} {
		t.Run(tc.a+" vs "+tc.b, func(t *testing.T) {
			gotA, err := agentid.FromDirectory(tc.a)
			if err != nil {
				t.Fatalf("FromDirectory(%q): %v", tc.a, err)
			}
			gotB, err := agentid.FromDirectory(tc.b)
			if err != nil {
				t.Fatalf("FromDirectory(%q): %v", tc.b, err)
			}
			if gotA == gotB {
				t.Errorf("FromDirectory folded two distinct hosts together: %q and %q both -> %q",
					tc.a, tc.b, gotA)
			}
		})
	}
}

// TestFromDirectory_idempotent matters because normalization happens at more than
// one boundary — the Exchange normalizes what it stores, the Broker normalizes both
// sides of its self-action comparison, and agentreg normalizes again on a value a
// caller already normalized. A second pass must be a no-op, or the boundaries could
// disagree about an already-normalized value. This is the property that lets the
// double normalization be a documented no-op rather than a latent bug, so every
// folding axis is re-checked here rather than a representative one.
func TestFromDirectory_idempotent(t *testing.T) {
	for _, ref := range []string{
		"https://agent.example",
		"identity:8080",
		"https://Agent.Example.",
		"https://agent.example:443",
		"https://agent.example:0443",
		"https://identity:08080",
		"https://приклад.юа",
		"[::1]:8080",
		"127.0.0.1",
		"127.0.0.1:8080",
		"https://[0:0:0:0:0:0:0:1]",
		"https://[2001:DB8::1]:08080",
		"https://[::ffff:7f00:1]",
	} {
		t.Run(ref, func(t *testing.T) {
			once, err := agentid.FromDirectory(ref)
			if err != nil {
				t.Fatalf("FromDirectory(%q): %v", ref, err)
			}
			twice, err := agentid.FromDirectory(once)
			if err != nil {
				t.Fatalf("FromDirectory(%q) (second pass): %v", once, err)
			}
			if once != twice {
				t.Errorf("not idempotent: %q -> %q -> %q", ref, once, twice)
			}
		})
	}
}

// TestDirectoryFromRequest_repeatedHeaderRefused pins the parity that matters at an
// authentication boundary. A field repeated across two lines contributes BOTH
// values to the RFC 9421 signature base, joined by ", ", so the signature commits
// to both. Reading only the first line would derive the identity from one value
// while the signature covered two — the divergence the SDK's own reader documents
// and refuses, and this stack has to refuse it identically or a request would
// authorize differently depending on which door it came through.
func TestDirectoryFromRequest_repeatedHeaderRefused(t *testing.T) {
	h := http.Header{}
	h.Add(agentid.SignatureAgentHeader, `"https://victim.example"`)
	h.Add(agentid.SignatureAgentHeader, `"https://attacker.example"`)

	directory := agentid.DirectoryFromRequest(h)
	if _, err := agentid.FromDirectory(directory); err == nil {
		t.Errorf("a repeated Signature-Agent resolved to an identity (%q); "+
			"want refusal — the signature committed to both values", directory)
	}
	// A single occurrence still reads normally: this refuses ambiguity, not the
	// header.
	single := http.Header{}
	single.Add(agentid.SignatureAgentHeader, `"https://agent.example"`)
	got, err := agentid.FromDirectory(agentid.DirectoryFromRequest(single))
	if err != nil {
		t.Fatalf("single Signature-Agent: %v", err)
	}
	if got != "agent.example" {
		t.Errorf("single Signature-Agent -> %q; want %q", got, "agent.example")
	}
}

// TestFromDirectory_rejectsNonHosts covers the negative path. Each of these would
// otherwise land in the agents table as an identity, or be aimed at as a fetch
// host. The two Signature-Agent forms RAMP declines are here on purpose: the
// sf-dictionary and the data: URI must fail to normalize, which is what keeps the
// refusal from depending on a parser elsewhere happening to reject them.
func TestFromDirectory_rejectsNonHosts(t *testing.T) {
	// The shared corpus plus this package's own missing-value cases. Missing is a
	// different class from malformed — the layers above answer it differently — so
	// the corpus excludes it and each layer keeps its own.
	missing := []agentidtest.NonHostValue{
		{Name: "empty", Value: ""},
		{Name: "whitespace", Value: "   "},
	}
	shared := agentidtest.NonHostValues()
	cases := make([]agentidtest.NonHostValue, 0, len(missing)+len(shared))
	cases = append(append(cases, missing...), shared...)
	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			got, err := agentid.FromDirectory(tc.Value)
			if err == nil {
				t.Fatalf("FromDirectory(%q) = %q, nil; want an error — this value would become an agent identity", tc.Value, got)
			}
			if got != "" {
				t.Errorf("FromDirectory(%q) returned %q alongside its error; want empty", tc.Value, got)
			}
			if !strings.Contains(err.Error(), "agentid:") {
				t.Errorf("error %q is not attributed to this package", err)
			}
		})
	}
}
