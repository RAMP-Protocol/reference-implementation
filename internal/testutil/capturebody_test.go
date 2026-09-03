//go:build integration

package testutil

import (
	"bytes"
	"compress/gzip"
	"io"
	"net/http"
	"testing"
)

// stubRoundTripper answers one canned response, so these cases drive CaptureBody
// without a server.
type stubRoundTripper struct {
	body     []byte
	encoding string
}

func (s stubRoundTripper) RoundTrip(*http.Request) (*http.Response, error) {
	header := http.Header{}
	if s.encoding != "" {
		header.Set("Content-Encoding", s.encoding)
	}
	return &http.Response{
		StatusCode: http.StatusOK,
		Header:     header,
		Body:       io.NopCloser(bytes.NewReader(s.body)),
	}, nil
}

// roundTrip drives one response through a capture and returns the capture plus
// the bytes the CLIENT was re-served.
func roundTrip(t *testing.T, base stubRoundTripper) (*CaptureBody, []byte) {
	t.Helper()
	capture := &CaptureBody{Base: base}
	resp, err := capture.RoundTrip(&http.Request{})
	if err != nil {
		t.Fatalf("round trip: %v", err)
	}
	served, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read re-served body: %v", err)
	}
	return capture, served
}

// gzipped compresses raw the way a Connect server would.
func gzipped(t *testing.T, raw string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write([]byte(raw)); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// TestCapture_DecodesAGzipResponseAndReservesTheOriginal is the happy path, and
// it pins both halves: the capture holds the DECODED bytes a wire assertion can
// read, and the client is handed back the bytes it was going to decode itself.
func TestCapture_DecodesAGzipResponseAndReservesTheOriginal(t *testing.T) {
	t.Parallel()
	const want = `{"ver":"1.0","rejected":0}`
	compressed := gzipped(t, want)
	capture, served := roundTrip(t, stubRoundTripper{body: compressed, encoding: "gzip"})
	if got := string(capture.Body(t)); got != want {
		t.Errorf("captured %q, want the decompressed %q", got, want)
	}
	if !bytes.Equal(served, compressed) {
		t.Error("the client was re-served something other than the original bytes, so its " +
			"own decoder sees a body the server never sent")
	}
}

// TestCapture_KeepsAPlainResponseAsItArrived is the negative case for the branch
// above: without a gzip header nothing is decompressed.
func TestCapture_KeepsAPlainResponseAsItArrived(t *testing.T) {
	t.Parallel()
	const want = `{"ver":"1.0"}`
	capture, _ := roundTrip(t, stubRoundTripper{body: []byte(want)})
	if got := string(capture.Body(t)); got != want {
		t.Errorf("captured %q, want %q", got, want)
	}
}

// TestCapture_RefusesToHandBackBytesItCouldNotDecompress is the case this
// accessor exists for. A response labelled gzip that is not gzip used to leave
// the COMPRESSED bytes in the capture, so the next assertion reported "body is
// not JSON" with binary quoted underneath — a true failure naming the wrong
// cause. The bytes are withheld now and the reason is recorded.
//
// Read through the unexported fields rather than through Body, because Body's
// whole job here is to end the test.
func TestCapture_RefusesToHandBackBytesItCouldNotDecompress(t *testing.T) {
	t.Parallel()
	notGzip := []byte(`{"ver":"1.0"}`)
	capture, served := roundTrip(t, stubRoundTripper{body: notGzip, encoding: "gzip"})
	if capture.decodeErr == nil {
		t.Fatal("a response labelled gzip that does not decompress was accepted silently")
	}
	if capture.body != nil {
		t.Errorf("the capture kept %q, and handing those out is what named the wrong "+
			"cause several assertions later", capture.body)
	}
	if !bytes.Equal(served, notGzip) {
		t.Error("the client must still be re-served the original bytes; a capture that " +
			"cannot read a body is not a reason to change what the client receives")
	}
}
