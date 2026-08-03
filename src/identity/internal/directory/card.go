package directory

import (
	"encoding/json"
	"fmt"
)

// BuildCard serializes a Signature Agent Card to the JSON bytes served at CardPath.
// It is a thin marshal kept separate from the store so the wire shape has one
// owner and can be unit-tested without a database.
func BuildCard(c Card) ([]byte, error) {
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("directory: BuildCard: %w", err)
	}
	return raw, nil
}
