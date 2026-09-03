package exchreg

import (
	"crypto/sha256"
	"encoding/hex"

	"github.com/RAMP-Protocol/protocol/sdk/go/helpers"
)

// compiled is one schema's answer, held under the hash of the bytes it came
// from. The refusal verdicts are held too: a schema this adapter cannot use is
// a stable property of those bytes, so re-deciding it per call would pay exactly
// the cost the SDK's caps exist to bound.
type compiled struct {
	schema  *helpers.RegistrationSchema
	verdict helpers.SchemaVerdict
}

// compile returns the validator for these exact served bytes, compiling at most
// once per distinct document.
func (r *Reader) compile(raw []byte) (*helpers.RegistrationSchema, helpers.SchemaVerdict) {
	sum := sha256.Sum256(raw)
	key := hex.EncodeToString(sum[:])
	if hit, ok := r.compiled.Get(key); ok {
		return hit.schema, hit.verdict
	}
	schema, verdict := helpers.CompileRegistrationSchema(raw)
	if verdict != helpers.SchemaAccepted {
		// Held as nil rather than as whatever the SDK returned alongside a
		// refusal: a nil validator reports no failures, which is the client
		// behaviour a refused schema calls for, and keeping a half-usable value
		// around would invite a caller to use it.
		schema = nil
	}
	r.compiled.Add(key, compiled{schema: schema, verdict: verdict})
	return schema, verdict
}
