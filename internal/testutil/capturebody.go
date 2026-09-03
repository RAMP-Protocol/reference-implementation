//go:build integration

package testutil

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"
)

// CaptureBody tees a response body so a test can assert on the EXACT bytes the
// server emitted while the Connect client still decodes the typed message
// normally. Wrap it around a signing transport, not inside one, so the request
// is signed before the response is teed.
//
// JSON is the only wire where the response codec is observable: gRPC and proto
// framing carry every field regardless, so a test that wants to see what the
// codec did has to drive the call over Connect-JSON and read the bytes here.
type CaptureBody struct {
	Base http.RoundTripper
	body []byte
	// decodeErr is why body is empty, when a gzip response would not
	// decompress. Kept rather than dropped: returning the COMPRESSED bytes made
	// every assertion downstream fail on the wrong cause — "body is not JSON"
	// with a block of binary quoted underneath, or a presence check reporting a
	// body that appears to be missing every field.
	decodeErr error
}

// Body returns the decoded bytes of the last response, or nil before the first.
//
// It takes tb so a response that could not be decompressed fails HERE, naming
// gzip, instead of surfacing as a body that makes no sense several assertions
// later. Every caller is a test and already holds one.
func (c *CaptureBody) Body(tb testing.TB) []byte {
	tb.Helper()
	if c.decodeErr != nil {
		tb.Fatalf("captured response was gzip and did not decompress: %v", c.decodeErr)
	}
	return c.body
}

// RoundTrip reads the response body, keeps a decoded copy, and re-serves the
// original bytes so the client's own decoder is unaffected.
func (c *CaptureBody) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := c.Base.RoundTrip(req)
	if err != nil || resp.Body == nil {
		return resp, err
	}
	raw, rerr := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if rerr != nil {
		return nil, rerr
	}
	// Connect advertises gzip, so the server may compress the JSON. Keep the
	// DECODED bytes for wire-shape inspection and re-serve the original raw ones.
	// The client's own decoder reads the raw bytes either way, so a decode
	// failure here is this capture's problem alone and is recorded rather than
	// dropped — the compressed bytes are never handed out as if they were the
	// body.
	c.body, c.decodeErr = raw, nil
	if resp.Header.Get("Content-Encoding") == "gzip" {
		c.body, c.decodeErr = gunzip(raw)
	}
	resp.Body = io.NopCloser(bytes.NewReader(raw))
	return resp, nil
}

// gunzip decompresses raw, or reports why it could not.
func gunzip(raw []byte) ([]byte, error) {
	zr, err := gzip.NewReader(bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	defer func() { _ = zr.Close() }()
	dec, err := io.ReadAll(zr)
	if err != nil {
		return nil, err
	}
	return dec, nil
}
