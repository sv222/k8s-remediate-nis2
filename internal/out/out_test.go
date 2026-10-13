package out

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nis2rem/k8s-remediate-nis2/internal/finding"
	"github.com/nis2rem/k8s-remediate-nis2/internal/render"
)

func TestWriteTree(t *testing.T) {
	dir := t.TempDir()
	files := []render.RenderedFile{
		{RelPath: "terraform/x.tf", Content: "# x"},
		{RelPath: "kyverno/y.yaml", Content: "# y"},
	}
	rows := []SummaryRow{{Scanner: "prowler", CheckID: "c", ResourceID: "r",
		Articles: []string{"NIS2 Art.21(2)(d)"}, Files: []string{"terraform/x.tf"}, Status: "remediated"}}
	if err := Write(dir, files, rows); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "terraform", "x.tf")); err != nil {
		t.Error("x.tf missing")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "mapping.md"))
	if !strings.Contains(string(b), "NIS2 Art.21(2)(d)") {
		t.Errorf("mapping.md lacks article:\n%s", b)
	}
}

func TestWriteEvidence(t *testing.T) {
	dir := t.TempDir()
	fs := []finding.Finding{{Scanner: "prowler", CheckID: "c", Status: "FAIL", ResourceID: "r"}}
	rows := []SummaryRow{{Scanner: "prowler", CheckID: "c", ResourceID: "r", Status: "remediated"}}
	if err := WriteEvidence(dir, fs, rows, []string{"testdata/v4.json"}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "evidence.md"))
	s := string(b)
	for _, want := range []string{
		"Technical Remediation & Evidence Assistant for NIS2/DORA",
		"risk acceptance remains with the client's management",
		"SHA-256",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("evidence.md missing %q", want)
		}
	}
}
