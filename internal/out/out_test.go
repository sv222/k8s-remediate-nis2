package out

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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
