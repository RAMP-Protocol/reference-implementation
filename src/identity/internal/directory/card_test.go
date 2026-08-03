package directory_test

import (
	"encoding/json"
	"testing"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/identity/internal/directory"
)

func TestBuildCard_FieldShape(t *testing.T) {
	t.Parallel()
	card := directory.Card{
		ClientName: "Acme Crawler",
		ClientURI:  "https://agent-7f3a.rampmcp.org",
		Contacts:   []string{"mailto:ops@acme.example"},
		Purpose:    "ai-index",
	}
	raw, err := directory.BuildCard(card)
	if err != nil {
		t.Fatalf("BuildCard: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	for k, want := range map[string]any{
		"client_name": "Acme Crawler",
		"client_uri":  "https://agent-7f3a.rampmcp.org",
		"purpose":     "ai-index",
	} {
		if got[k] != want {
			t.Errorf("%s = %v, want %v", k, got[k], want)
		}
	}
	contacts, ok := got["contacts"].([]any)
	if !ok || len(contacts) != 1 || contacts[0] != "mailto:ops@acme.example" {
		t.Errorf("contacts = %v, want [mailto:ops@acme.example]", got["contacts"])
	}
}

func TestBuildCard_OmitsEmptyOptionalFields(t *testing.T) {
	t.Parallel()
	raw, err := directory.BuildCard(directory.Card{
		ClientName: "Minimal",
		ClientURI:  "https://agent-1.rampmcp.org",
	})
	if err != nil {
		t.Fatalf("BuildCard: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(raw, &got); err != nil {
		t.Fatalf("parse: %v", err)
	}
	if _, present := got["contacts"]; present {
		t.Error("contacts present, want omitted when empty")
	}
	if _, present := got["purpose"]; present {
		t.Error("purpose present, want omitted when empty")
	}
}
