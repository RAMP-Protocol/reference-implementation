package httpsig

import (
	"fmt"
	"net/http"

	"github.com/dunglas/httpsfv"
)

// parseAllSignatures extracts ALL signature labels from the Signature-Input and
// Signature headers using the RFC 8941 structured-field parser (httpsfv).
// Returns one Params per label in Signature-Input order plus a map of
// label→raw signature bytes. Handles 0, 1, or N signatures.
//
// Missing Signature-Input → ErrMissingSignatureInput; missing Signature →
// ErrMissingSignature; any structured-field parse failure → wrapped
// ErrMalformedSignatureInput so callers can branch on the sentinel.
func parseAllSignatures(h http.Header) ([]Params, map[string][]byte, error) {
	inputValues := h.Values("Signature-Input")
	if len(inputValues) == 0 {
		return nil, nil, ErrMissingSignatureInput
	}
	sigValues := h.Values("Signature")
	if len(sigValues) == 0 {
		return nil, nil, ErrMissingSignature
	}

	inputDict, err := httpsfv.UnmarshalDictionary(inputValues)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: Signature-Input: %w", ErrMalformedSignatureInput, err)
	}
	sigDict, err := httpsfv.UnmarshalDictionary(sigValues)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: Signature: %w", ErrMalformedSignatureInput, err)
	}

	names := inputDict.Names()
	if len(names) == 0 {
		return nil, nil, fmt.Errorf("%w: no labels found", ErrMalformedSignatureInput)
	}

	allParams := make([]Params, 0, len(names))
	sigMap := make(map[string][]byte, len(names))
	for _, label := range names {
		params, perr := parseInputLabel(inputDict, label)
		if perr != nil {
			return nil, nil, perr
		}
		allParams = append(allParams, params)

		sigBytes, serr := parseSigLabel(sigDict, label)
		if serr != nil {
			return nil, nil, serr
		}
		sigMap[label] = sigBytes
	}
	return allParams, sigMap, nil
}

// parseInputLabel converts one Signature-Input dictionary member (an inner list
// with covered components + signature params) into a Params.
func parseInputLabel(d *httpsfv.Dictionary, label string) (Params, error) {
	member, ok := d.Get(label)
	if !ok {
		return Params{}, fmt.Errorf("%w: label %q absent", ErrMalformedSignatureInput, label)
	}
	list, ok := member.(httpsfv.InnerList)
	if !ok {
		return Params{}, fmt.Errorf("%w: label %q is not an inner list", ErrMalformedSignatureInput, label)
	}

	covered := make([]CoveredComponent, 0, len(list.Items))
	for _, item := range list.Items {
		comp, cerr := coveredFromItem(item)
		if cerr != nil {
			return Params{}, cerr
		}
		covered = append(covered, comp)
	}

	params := Params{Label: label, Covered: covered}
	if err := applySignatureParams(&params, list.Params); err != nil {
		return Params{}, err
	}
	if params.KeyID == "" {
		return Params{}, fmt.Errorf("%w: keyid required", ErrMalformedSignatureInput)
	}
	return params, nil
}

// coveredFromItem converts one structured-field item (a covered-component
// identifier such as "@method" or "signature";key="sig1") into a
// CoveredComponent. Only string-valued component params are carried (the
// forwarding-chain key= param is the only one RAMP emits).
func coveredFromItem(item httpsfv.Item) (CoveredComponent, error) {
	name, ok := item.Value.(string)
	if !ok {
		return CoveredComponent{}, fmt.Errorf("%w: component identifier not a string", ErrMalformedSignatureInput)
	}
	comp := CoveredComponent{Name: name}
	if item.Params == nil {
		return comp, nil
	}
	for _, k := range item.Params.Names() {
		v, present := item.Params.Get(k)
		if !present {
			continue
		}
		sv, isStr := v.(string)
		if !isStr {
			return CoveredComponent{}, fmt.Errorf("%w: component param %q not a string", ErrMalformedSignatureInput, k)
		}
		comp.Params = append(comp.Params, ComponentParam{Key: k, Val: sv})
	}
	return comp, nil
}

// applySignatureParams reads the keyid/alg/tag/nonce/created/expires signature
// parameters off the inner list's params into p. A parameter that is absent
// leaves its field at the zero value; one that carries the wrong structured-field
// type is an ErrMalformedSignatureInput.
func applySignatureParams(p *Params, params *httpsfv.Params) error {
	if params == nil {
		return nil
	}
	strFields := []struct {
		name string
		dst  *string
	}{{"keyid", &p.KeyID}, {"alg", &p.Alg}, {"tag", &p.Tag}, {"nonce", &p.Nonce}}
	for _, f := range strFields {
		if err := stringParam(params, f.name, f.dst); err != nil {
			return err
		}
	}
	intFields := []struct {
		name string
		dst  *int64
	}{{"created", &p.Created}, {"expires", &p.Expires}}
	for _, f := range intFields {
		if err := intParam(params, f.name, f.dst); err != nil {
			return err
		}
	}
	return nil
}

// stringParam reads one string-valued signature parameter into dst, leaving dst
// untouched when the parameter is absent.
func stringParam(params *httpsfv.Params, name string, dst *string) error {
	v, ok := params.Get(name)
	if !ok {
		return nil
	}
	s, isStr := v.(string)
	if !isStr {
		return fmt.Errorf("%w: %s not a string", ErrMalformedSignatureInput, name)
	}
	*dst = s
	return nil
}

// intParam reads one integer-valued signature parameter into dst, leaving dst
// untouched when the parameter is absent.
func intParam(params *httpsfv.Params, name string, dst *int64) error {
	v, ok := params.Get(name)
	if !ok {
		return nil
	}
	n, isInt := v.(int64)
	if !isInt {
		return fmt.Errorf("%w: %s not an integer", ErrMalformedSignatureInput, name)
	}
	*dst = n
	return nil
}

// parseSigLabel extracts the raw signature bytes for label from the Signature
// dictionary. Each member is an item whose value is a byte sequence ([]byte).
func parseSigLabel(d *httpsfv.Dictionary, label string) ([]byte, error) {
	member, ok := d.Get(label)
	if !ok {
		return nil, fmt.Errorf("%w: Signature label %q not present", ErrMalformedSignatureInput, label)
	}
	item, ok := member.(httpsfv.Item)
	if !ok {
		return nil, fmt.Errorf("%w: Signature label %q is not an item", ErrMalformedSignatureInput, label)
	}
	raw, ok := item.Value.([]byte)
	if !ok {
		return nil, fmt.Errorf("%w: Signature value not a byte sequence", ErrMalformedSignatureInput)
	}
	return raw, nil
}

// ParseSignatureLabels parses the Signature-Input + Signature headers off h and
// returns one Params per label, in header order. It is the exported entry point
// for callers outside this package (e.g. the relay integration test) that need
// to inspect the labels/keyids of a multi-signature request without
// re-implementing the structured-field parser. Returns an error when either
// header is absent or any label is malformed.
func ParseSignatureLabels(h http.Header) ([]Params, error) {
	params, _, err := parseAllSignatures(h)
	return params, err
}

// componentParam returns the value of the named parameter on c, or "" if absent.
// Retained for the forwarding-chain link inspection in enforceSignatureChain.
func componentParam(c CoveredComponent, key string) string {
	for _, p := range c.Params {
		if p.Key == key {
			return p.Val
		}
	}
	return ""
}
