package httpsig

import (
	"fmt"
	"strings"
)

// parseMultiLabelInput splits a Signature-Input header value on top-level
// commas, returning individual label=(...);params strings.
func parseMultiLabelInput(raw string) []string {
	var out []string
	var cur strings.Builder
	inParen := 0
	inQuote := false

	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == '"' && (i == 0 || raw[i-1] != '\\') {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if inQuote {
			cur.WriteByte(c)
			continue
		}
		if c == '(' {
			inParen++
			cur.WriteByte(c)
			continue
		}
		if c == ')' {
			inParen--
			cur.WriteByte(c)
			continue
		}
		if c == ',' && inParen == 0 {
			if cur.Len() > 0 {
				out = append(out, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// parseComponentList parses a space-separated list of RFC 9421 component
// identifiers, each a quoted name optionally followed by `;param="value"`
// parameters with no intervening space. Only string-valued parameters are
// supported (sufficient for the forwarding-chain `"signature";key="sig1"`).
// Example:
//
//	`"@method" "content-digest" "signature";key="sig1"`
//	→ [{@method} {content-digest} {signature key=sig1}]
func parseComponentList(inner string) ([]CoveredComponent, error) {
	var out []CoveredComponent
	i := 0
	for i < len(inner) {
		for i < len(inner) && (inner[i] == ' ' || inner[i] == '\t') {
			i++
		}
		if i >= len(inner) {
			break
		}
		comp, next, err := parseOneComponent(inner, i)
		if err != nil {
			return nil, err
		}
		out = append(out, comp)
		i = next
	}
	return out, nil
}

// parseOneComponent parses a single component identifier starting at index i
// (which must point at the opening quote). Returns the component and the index
// just past it (past any trailing parameters).
func parseOneComponent(inner string, i int) (CoveredComponent, int, error) {
	if inner[i] != '"' {
		return CoveredComponent{}, 0,
			fmt.Errorf("%w: expected quoted identifier at %q", ErrMalformedSignatureInput, inner[i:])
	}
	j := i + 1
	for j < len(inner) && inner[j] != '"' {
		j++
	}
	if j >= len(inner) {
		return CoveredComponent{}, 0, fmt.Errorf("%w: unterminated quoted string", ErrMalformedSignatureInput)
	}
	comp := CoveredComponent{Name: inner[i+1 : j]}
	i = j + 1
	for i < len(inner) && inner[i] == ';' {
		p, next, err := parseComponentParam(inner, i+1)
		if err != nil {
			return CoveredComponent{}, 0, err
		}
		comp.Params = append(comp.Params, p)
		i = next
	}
	return comp, i, nil
}

// parseComponentParam parses a `key="value"` parameter starting at index i
// (just past the leading semicolon). Returns the param and the index past it.
func parseComponentParam(inner string, i int) (ComponentParam, int, error) {
	ks := i
	for i < len(inner) && inner[i] != '=' {
		i++
	}
	if i >= len(inner) {
		return ComponentParam{}, 0, fmt.Errorf("%w: component param missing '='", ErrMalformedSignatureInput)
	}
	key := strings.TrimSpace(inner[ks:i])
	i++ // consume '='
	if i >= len(inner) || inner[i] != '"' {
		return ComponentParam{}, 0, fmt.Errorf("%w: component param value not quoted", ErrMalformedSignatureInput)
	}
	vs := i + 1
	j := vs
	for j < len(inner) && inner[j] != '"' {
		j++
	}
	if j >= len(inner) {
		return ComponentParam{}, 0, fmt.Errorf("%w: unterminated component param value", ErrMalformedSignatureInput)
	}
	return ComponentParam{Key: key, Val: inner[vs:j]}, j + 1, nil
}

// splitParams splits "keyid=\"x\";alg=\"ed25519\";created=1" on top-level
// semicolons while preserving quoted values.
func splitParams(s string) []string {
	s = strings.TrimPrefix(s, ";")
	var out []string
	var cur strings.Builder
	inQuote := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == '"' {
			inQuote = !inQuote
			cur.WriteByte(c)
			continue
		}
		if c == ';' && !inQuote {
			if cur.Len() > 0 {
				out = append(out, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}

// parseMultiLabelSignature splits a Signature header value on top-level commas.
// Format: `sig1=:base64:, sig2=:base64:`.
func parseMultiLabelSignature(raw string) []string {
	var out []string
	var cur strings.Builder
	inByteSeq := false

	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if c == ':' {
			inByteSeq = !inByteSeq
			cur.WriteByte(c)
			continue
		}
		if c == ',' && !inByteSeq {
			if cur.Len() > 0 {
				out = append(out, strings.TrimSpace(cur.String()))
				cur.Reset()
			}
			continue
		}
		cur.WriteByte(c)
	}
	if cur.Len() > 0 {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out
}
