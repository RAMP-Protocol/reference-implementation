// Package registry reconciles marketplace bootstrap entries with the database
// and refreshes marketplace health in the background.
package registry

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"

	"gopkg.in/yaml.v3"

	"gitlab.postindustria.com/pi-ai/prebid-agentic-content-access/src/broker/internal/repo"
)

// BootstrapEntry models one marketplace definition from bootstrap.yaml.
type BootstrapEntry struct {
	ID                string   `yaml:"id"`
	Domain            string   `yaml:"domain"`
	Endpoint          string   `yaml:"endpoint"`
	TrustLevel        string   `yaml:"trust_level"`
	Priority          int32    `yaml:"priority"`
	SupportedProfiles []string `yaml:"supported_profiles"`
}

// bootstrapFile is the YAML root shape.
type bootstrapFile struct {
	Marketplaces []BootstrapEntry `yaml:"marketplaces"`
}

// LoadFromReader decodes bootstrap entries from an arbitrary reader.
func LoadFromReader(r io.Reader) ([]BootstrapEntry, error) {
	var file bootstrapFile
	if err := yaml.NewDecoder(r).Decode(&file); err != nil {
		return nil, fmt.Errorf("registry: decode bootstrap: %w", err)
	}
	for i := range file.Marketplaces {
		if err := validate(&file.Marketplaces[i]); err != nil {
			return nil, err
		}
	}
	return file.Marketplaces, nil
}

// LoadFromFile decodes bootstrap entries from path.
func LoadFromFile(path string) ([]BootstrapEntry, error) {
	f, err := os.Open(path) //nolint:gosec // operator-controlled path
	if err != nil {
		return nil, fmt.Errorf("registry: open bootstrap: %w", err)
	}
	defer func() { _ = f.Close() }()
	return LoadFromReader(f)
}

// Reconcile upserts every bootstrap entry into the marketplace repo.
func Reconcile(ctx context.Context, marketRepo repo.MarketplaceRepo, entries []BootstrapEntry) error {
	for _, e := range entries {
		_, err := marketRepo.UpsertFromBootstrap(ctx, repo.Marketplace{
			ID:                e.ID,
			Domain:            e.Domain,
			Endpoint:          e.Endpoint,
			TrustLevel:        e.TrustLevel,
			SupportedProfiles: e.SupportedProfiles,
			Priority:          e.Priority,
		})
		if err != nil {
			return fmt.Errorf("registry: upsert %s: %w", e.ID, err)
		}
	}
	return nil
}

func validate(e *BootstrapEntry) error {
	if e.ID == "" {
		return errors.New("registry: marketplace id is required")
	}
	if e.Domain == "" {
		return fmt.Errorf("registry: domain is required for %s", e.ID)
	}
	if e.Endpoint == "" {
		return fmt.Errorf("registry: endpoint is required for %s", e.ID)
	}
	if e.TrustLevel == "" {
		e.TrustLevel = "DISCOVERED"
	}
	return nil
}
