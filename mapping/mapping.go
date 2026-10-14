package mapping

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"fmt"
	"sync"

	"sigs.k8s.io/yaml"

	templates "github.com/sv222/k8s-remediate-nis2"
	"github.com/sv222/k8s-remediate-nis2/internal/finding"
)

var TemplatesFS = templates.FS

//go:embed mappings.yaml
var mappingsFS embed.FS

type doc struct {
	Version int     `json:"version"`
	Entries []Entry `json:"entries"`
}

type Entry struct {
	Scanner         string            `json:"scanner"`
	CheckID         string            `json:"check_id"`
	BenchmarkIDs    map[string]string `json:"benchmark_ids"`
	Title           string            `json:"title"`
	Articles        []string          `json:"articles"`
	Templates       []string          `json:"templates"`
	SharedTemplates []string          `json:"shared_templates"`
	Guidance        string            `json:"guidance"`
	Regional        bool              `json:"regional"`
	RequiresRegion  bool              `json:"requires_region"`
	FollowUp        string            `json:"follow_up"`
	Caution         string            `json:"caution"`
	Group           string            `json:"group"`
	Rank            int               `json:"rank"`
}

var (
	loadOnce sync.Once
	loaded   []Entry
	loadErr  error

	docVersion int
	docSHA     string
)

func Info() (int, string) {
	_, _ = Load()
	return docVersion, docSHA
}

func Load() ([]Entry, error) {
	loadOnce.Do(func() {
		loaded, loadErr = parse()
	})
	return loaded, loadErr
}

func parse() ([]Entry, error) {
	data, err := mappingsFS.ReadFile("mappings.yaml")
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(data)
	docSHA = hex.EncodeToString(sum[:])
	var d doc
	if err := yaml.UnmarshalStrict(data, &d); err != nil {
		return nil, fmt.Errorf("mappings.yaml: %w", err)
	}
	if d.Version != 1 {
		return nil, fmt.Errorf("unsupported mapping version %d", d.Version)
	}
	docVersion = d.Version
	if err := validate(d.Entries); err != nil {
		return nil, fmt.Errorf("mappings.yaml: %w", err)
	}
	return d.Entries, nil
}

func validate(entries []Entry) error {
	seen := map[string]bool{}
	for i, e := range entries {
		if len(e.Articles) == 0 {
			return fmt.Errorf("entry %d (%s): no articles", i, e.Title)
		}
		if len(e.Templates) == 0 && len(e.SharedTemplates) == 0 && e.Guidance == "" {
			return fmt.Errorf("entry %d (%s): no templates and no guidance", i, e.Title)
		}
		if (e.Group == "") != (e.Rank == 0) {
			return fmt.Errorf("entry %d (%s): group and rank go together", i, e.Title)
		}
		var keys []string
		switch e.Scanner {
		case "prowler":
			if e.CheckID == "" || len(e.BenchmarkIDs) > 0 {
				return fmt.Errorf("entry %d (%s): prowler entries need check_id only", i, e.Title)
			}
			keys = append(keys, "prowler|"+e.CheckID)
		case "kube-bench":
			if e.CheckID != "" || len(e.BenchmarkIDs) == 0 {
				return fmt.Errorf("entry %d (%s): kube-bench entries need benchmark_ids only", i, e.Title)
			}
			for b, id := range e.BenchmarkIDs {
				if b == "" || id == "" {
					return fmt.Errorf("entry %d (%s): empty benchmark or id", i, e.Title)
				}
				keys = append(keys, "kube-bench|"+b+"|"+id)
			}
		default:
			return fmt.Errorf("entry %d (%s): unknown scanner %q", i, e.Title, e.Scanner)
		}
		for _, k := range keys {
			if seen[k] {
				return fmt.Errorf("duplicate mapping %s", k)
			}
			seen[k] = true
		}
	}
	return nil
}

func For(f finding.Finding) (Entry, bool, error) {
	entries, err := Load()
	if err != nil {
		return Entry{}, false, err
	}
	for _, e := range entries {
		if e.Scanner != f.Scanner {
			continue
		}
		switch e.Scanner {
		case "prowler":
			if e.CheckID == f.CheckID {
				return e, true, nil
			}
		case "kube-bench":
			if id, ok := e.BenchmarkIDs[f.Benchmark]; ok && id == f.CheckID {
				return e, true, nil
			}
		}
	}
	return Entry{}, false, nil
}
