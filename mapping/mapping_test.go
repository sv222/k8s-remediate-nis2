package mapping

import (
	"testing"

	"github.com/nis2rem/k8s-remediate-nis2/internal/finding"
)

func TestLoadAndLookup(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 8 {
		t.Fatalf("entries = %d, want >= 8", len(entries))
	}
	e, ok := For(finding.Finding{Scanner: "prowler", CheckID: "s3_bucket_public_access_block"})
	if !ok || len(e.Templates) != 1 || e.Templates[0] != "terraform/s3_public_access_block.tf" {
		t.Errorf("lookup failed: %+v ok=%v", e, ok)
	}
}

func TestTemplateCoverage(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		for _, tpl := range e.Templates {
			if _, err := TemplatesFS.ReadFile("templates/" + tpl); err != nil {
				t.Errorf("entry %s/%s references missing template %s", e.Scanner, e.CheckID, tpl)
			}
		}
	}
}
