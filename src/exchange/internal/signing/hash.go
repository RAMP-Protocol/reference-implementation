package signing

import "crypto/sha256"

// hashURL returns the SHA-256 digest of the signed URL for the
// transaction_log.signed_url_hash column (32 bytes, CHECK-constrained).
func hashURL(signed string) []byte {
	sum := sha256.Sum256([]byte(signed))
	out := make([]byte, len(sum))
	copy(out, sum[:])
	return out
}
