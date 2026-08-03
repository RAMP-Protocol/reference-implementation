package tigerbeetle

import (
	"errors"
	"testing"
)

func TestAccountID_DeterministicAndPrefixNamespaced(t *testing.T) {
	t.Parallel()
	a1, err := AccountID(PrefixAgent, "agent-1")
	if err != nil {
		t.Fatalf("AccountID: %v", err)
	}
	a2, err := AccountID(PrefixAgent, "agent-1")
	if err != nil {
		t.Fatalf("AccountID (repeat): %v", err)
	}
	if a1.Bytes() != a2.Bytes() {
		t.Fatal("AccountID is not deterministic for equal inputs")
	}
	// Equal business id under different prefixes must never collide.
	owner, _ := AccountID(PrefixOwner, "agent-1")
	platform, _ := AccountID(PrefixPlatform, "agent-1")
	switch {
	case a1.Bytes() == owner.Bytes(),
		a1.Bytes() == platform.Bytes(),
		owner.Bytes() == platform.Bytes():
		t.Fatal("prefixes collided for an equal business id")
	}
}

func TestAccountID_RejectsEmpty(t *testing.T) {
	t.Parallel()
	if _, err := AccountID(PrefixAgent, ""); !errors.Is(err, ErrEmptyID) {
		t.Fatalf("empty business id: want ErrEmptyID, got %v", err)
	}
}

func TestTransferID_DeterministicAndRejectsEmpty(t *testing.T) {
	t.Parallel()
	a, err := TransferID("idem-key-1")
	if err != nil {
		t.Fatalf("TransferID: %v", err)
	}
	b, _ := TransferID("idem-key-1")
	if a.Bytes() != b.Bytes() {
		t.Fatal("TransferID is not deterministic for equal keys")
	}
	if _, err := TransferID(""); !errors.Is(err, ErrEmptyID) {
		t.Fatalf("empty key: want ErrEmptyID, got %v", err)
	}
}

func TestReduce_RejectsReservedIDs(t *testing.T) {
	t.Parallel()
	var zero [32]byte
	if _, err := reduce(zero); !errors.Is(err, ErrReservedID) {
		t.Fatalf("all-zero digest: want ErrReservedID, got %v", err)
	}
	var allFF [32]byte
	for i := range allFF {
		allFF[i] = 0xFF
	}
	if _, err := reduce(allFF); !errors.Is(err, ErrReservedID) {
		t.Fatalf("all-0xFF digest: want ErrReservedID, got %v", err)
	}
}

func TestReduce_ValidDigestPassesThrough(t *testing.T) {
	t.Parallel()
	var sum [32]byte
	sum[0], sum[15] = 0x01, 0x02 // low 16 bytes are non-reserved
	id, err := reduce(sum)
	if err != nil {
		t.Fatalf("reduce(valid): %v", err)
	}
	b := id.Bytes()
	if b[0] != 0x01 || b[15] != 0x02 {
		t.Fatalf("reduce dropped the low 16 bytes: got %v", b)
	}
}
