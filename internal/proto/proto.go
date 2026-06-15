// Package proto is a thin re-export of the RAMP and CoMP proto types.
//
// Importing from this package instead of directly from the proto module
// keeps the canonical import path visible in one place and anchors the
// go.mod require on github.com/RAMP-Protocol/protocol.
package proto

import (
	compv1 "github.com/RAMP-Protocol/protocol/gen/go/comp/v1"
	rampv1 "github.com/RAMP-Protocol/protocol/gen/go/ramp/v1"
)

// Anchor forces the compiler to retain the proto imports so `go mod tidy`
// keeps the require directive. Remove once services import proto types directly.
var _ = []any{
	(*rampv1.ResourceQuery)(nil),
	(*compv1.Package)(nil),
}
