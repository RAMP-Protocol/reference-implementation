package service

import (
	"reflect"
	"testing"

	"google.golang.org/protobuf/types/known/structpb"
)

func TestStructToMap(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]any
		want map[string]string
	}{
		{
			name: "strings kept verbatim",
			in:   map[string]any{"legal_entity": "Acme AI Ltd", "email": "ops@acme.example"},
			want: map[string]string{"legal_entity": "Acme AI Ltd", "email": "ops@acme.example"},
		},
		{
			name: "integer-valued number renders without a decimal point",
			in:   map[string]any{"seats": float64(42)},
			want: map[string]string{"seats": "42"},
		},
		{
			name: "fractional number keeps only significant digits",
			in:   map[string]any{"rate": 1.5},
			want: map[string]string{"rate": "1.5"},
		},
		{
			name: "large number stays in decimal notation, no exponent",
			in:   map[string]any{"big": 1000000.0},
			want: map[string]string{"big": "1000000"},
		},
		{
			name: "bools render true/false",
			in:   map[string]any{"active": true, "trial": false},
			want: map[string]string{"active": "true", "trial": "false"},
		},
		{
			name: "null is omitted entirely",
			in:   map[string]any{"present": "x", "absent": nil},
			want: map[string]string{"present": "x"},
		},
		{
			name: "nested object encodes as compact, key-sorted JSON",
			in:   map[string]any{"address": map[string]any{"city": "Berlin", "country": "DE"}},
			want: map[string]string{"address": `{"city":"Berlin","country":"DE"}`},
		},
		{
			name: "nested array encodes as compact JSON",
			in:   map[string]any{"tags": []any{"a", "b"}},
			want: map[string]string{"tags": `["a","b"]`},
		},
		{
			name: "empty struct yields empty non-nil map",
			in:   map[string]any{},
			want: map[string]string{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s, err := structpb.NewStruct(tc.in)
			if err != nil {
				t.Fatalf("structpb.NewStruct: %v", err)
			}
			got := structToMap(s)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("structToMap = %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestStructToMap_NilStructIsEmptyNonNil(t *testing.T) {
	got := structToMap(nil)
	if got == nil {
		t.Fatal("structToMap(nil) = nil, want empty non-nil map")
	}
	if len(got) != 0 {
		t.Fatalf("structToMap(nil) = %#v, want empty", got)
	}
}
