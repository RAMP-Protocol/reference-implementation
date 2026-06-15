package transport

import (
	"errors"
	"fmt"

	connect "connectrpc.com/connect"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// EmitUnpopulatedJSONCodec replaces Connect-Go's default JSON codec so
// scalar fields with their zero value (e.g. Money.amount_minor=0 for a
// subscription-covered offer) appear in the JSON wire output. Connect's
// default protojson.MarshalOptions{} omits zero-valued scalars, which
// loses an observable the agent (and the obligation tests) depend on:
// "the subscription-covered offer carries price.amountMinor==0" cannot
// be asserted when amountMinor is omitted entirely from the response.
//
// Pass via connect.WithCodec(EmitUnpopulatedJSONCodec()) on the handler
// path. Both `json` and `json; charset=utf-8` content-types route here.
func EmitUnpopulatedJSONCodec() connect.Codec {
	return &emitUnpopulatedJSONCodec{name: "json"}
}

type emitUnpopulatedJSONCodec struct{ name string }

func (c *emitUnpopulatedJSONCodec) Name() string { return c.name }

func (c *emitUnpopulatedJSONCodec) Marshal(message any) ([]byte, error) {
	pm, ok := message.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("emit-unpopulated json codec: %T is not proto.Message", message)
	}
	return protojson.MarshalOptions{EmitUnpopulated: true}.Marshal(pm)
}

func (c *emitUnpopulatedJSONCodec) MarshalAppend(dst []byte, message any) ([]byte, error) {
	pm, ok := message.(proto.Message)
	if !ok {
		return nil, fmt.Errorf("emit-unpopulated json codec: %T is not proto.Message", message)
	}
	return protojson.MarshalOptions{EmitUnpopulated: true}.MarshalAppend(dst, pm)
}

func (c *emitUnpopulatedJSONCodec) Unmarshal(binary []byte, message any) error {
	pm, ok := message.(proto.Message)
	if !ok {
		return fmt.Errorf("emit-unpopulated json codec: %T is not proto.Message", message)
	}
	if len(binary) == 0 {
		return errors.New("zero-length payload is not a valid JSON object")
	}
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal(binary, pm)
}
