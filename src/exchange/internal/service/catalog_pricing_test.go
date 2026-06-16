package service

import (
	"encoding/json"
	"testing"
)

// TestPricingDoc_UnmarshalUnitCost confirms unit_cost / rate decode from both a
// JSON number and a quoted decimal string, so a stringy seed row can't 500 the
// DiscoverResources call when buildOffer unmarshals it.
func TestPricingDoc_UnmarshalUnitCost(t *testing.T) {
	cases := []struct {
		name string
		json string
		cost float64
		rate float64
	}{
		{"number", `{"model":"per_request","unit_cost":0.01,"rate":0.05,"currency":"USD"}`, 0.01, 0.05},
		{"string", `{"model":"per_request","unit_cost":"0.01","rate":"0.05","currency":"USD"}`, 0.01, 0.05},
		{"empty string", `{"unit_cost":"","currency":"USD"}`, 0, 0},
		{"missing", `{"currency":"USD"}`, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var p PricingDoc
			if err := json.Unmarshal([]byte(tc.json), &p); err != nil {
				t.Fatalf("unmarshal: %v", err)
			}
			if p.UnitCost != tc.cost {
				t.Errorf("UnitCost = %v, want %v", p.UnitCost, tc.cost)
			}
			if p.Rate != tc.rate {
				t.Errorf("Rate = %v, want %v", p.Rate, tc.rate)
			}
		})
	}
}

// TestPricingDoc_UnmarshalInvalid rejects a non-numeric string so genuinely
// malformed pricing still surfaces an error rather than silently becoming 0.
func TestPricingDoc_UnmarshalInvalid(t *testing.T) {
	var p PricingDoc
	if err := json.Unmarshal([]byte(`{"unit_cost":"free"}`), &p); err == nil {
		t.Fatal("expected error for non-numeric unit_cost string")
	}
}
