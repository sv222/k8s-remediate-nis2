package mapping

import (
	"embed"
	"fmt"

	"sigs.k8s.io/yaml"

	templates "github.com/nis2rem/k8s-remediate-nis2"
	"github.com/nis2rem/k8s-remediate-nis2/internal/finding"
)

// TemplatesFS embed.FS exposing templates/**. Re-exported from the root
// templates package (Go embed cannot reference parent directories).
var TemplatesFS = templates.FS

//go:embed mappings.yaml
var mappingsFS embed.FS

type doc struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

type Entry struct {
	Scanner   string   `json:"scanner"`
	CheckID   string   `json:"check_id"`
	Title     string   `json:"title"`
	Articles  []string `json:"articles"`
	Templates []string `json:"templates"`
}

func Load() ([]Entry, error) {
	data, err := mappingsFS.ReadFile("mappings.yaml")
	if err != nil {
		return nil, err
	}
	var d doc
	if err := yaml.UnmarshalStrict(data, &d); err != nil {
		return nil, fmt.Errorf("mappings.yaml: %w", err)
	}
	if d.Version != 1 {
		return nil, fmt.Errorf("unsupported mapping version %d", d.Version)
	}
	return d.Entries, nil
}

func For(f finding.Finding) (Entry, bool) {
	entries, err := Load()
	if err != nil {
		return Entry{}, false
	}
	for _, e := range entries {
		if e.Scanner == f.Scanner && e.CheckID == f.CheckID {
			return e, true
		}
	}
	return Entry{}, false
}
