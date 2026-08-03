package session_test

import (
	"errors"
	"testing"
	"time"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/internal/clock"
	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/session"
)

func newKey(b byte) []byte {
	k := make([]byte, session.KeyLen)
	for i := range k {
		k[i] = b
	}
	return k
}

type payload struct {
	Subject string `json:"subject"`
	Nonce   string `json:"nonce"`
}

func TestCodec_SealOpenRoundTrip(t *testing.T) {
	clk := clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	c, err := session.NewCodec(newKey(0x11), clk)
	if err != nil {
		t.Fatalf("NewCodec: %v", err)
	}
	in := payload{Subject: "user-1", Nonce: "abc"}
	sealed, err := c.Seal(in, 10*time.Minute)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	var out payload
	if err := c.Open(sealed, &out); err != nil {
		t.Fatalf("Open: %v", err)
	}
	if out != in {
		t.Errorf("round-trip = %+v, want %+v", out, in)
	}
}

func TestCodec_OpenExpired(t *testing.T) {
	clk := clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	c, _ := session.NewCodec(newKey(0x22), clk)
	sealed, _ := c.Seal(payload{Subject: "u"}, 5*time.Minute)

	clk.Advance(6 * time.Minute)
	var out payload
	if err := c.Open(sealed, &out); !errors.Is(err, session.ErrExpired) {
		t.Fatalf("Open after expiry = %v, want ErrExpired", err)
	}
}

func TestCodec_OpenTamperedIsInvalid(t *testing.T) {
	clk := clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	c, _ := session.NewCodec(newKey(0x33), clk)
	sealed, _ := c.Seal(payload{Subject: "u"}, 5*time.Minute)

	// Flip a byte in the middle of the compact serialization.
	b := []byte(sealed)
	b[len(b)/2] ^= 0x01
	var out payload
	if err := c.Open(string(b), &out); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("Open tampered = %v, want ErrInvalid", err)
	}
}

func TestCodec_OpenWrongKeyIsInvalid(t *testing.T) {
	clk := clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	sealer, _ := session.NewCodec(newKey(0x44), clk)
	sealed, _ := sealer.Seal(payload{Subject: "u"}, 5*time.Minute)

	opener, _ := session.NewCodec(newKey(0x55), clk)
	var out payload
	if err := opener.Open(sealed, &out); !errors.Is(err, session.ErrInvalid) {
		t.Fatalf("Open with wrong key = %v, want ErrInvalid", err)
	}
}

func TestNewCodec_RejectsBadKeyLen(t *testing.T) {
	clk := clock.NewDeterministic(time.Date(2026, 7, 21, 12, 0, 0, 0, time.UTC))
	if _, err := session.NewCodec([]byte("short"), clk); err == nil {
		t.Fatal("NewCodec with short key = nil error, want failure")
	}
	if _, err := session.NewCodec(newKey(0x66), nil); err == nil {
		t.Fatal("NewCodec with nil clock = nil error, want failure")
	}
}
