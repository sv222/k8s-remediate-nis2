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
	dir := filepath.Join(t.TempDir(), "nested", "out")
	files := []render.RenderedFile{
		{RelPath: "terraform/x__a.tf", Content: "x"},
		{RelPath: "kyverno/y.yaml", Content: "y"},
	}
	rows := []SummaryRow{{Scanner: "prowler", CheckID: "c", ResourceID: "r",
		Articles: []string{"NIS2 Art.21(2)(i)"}, Files: []string{"terraform/x__a.tf"}, Status: StatusRemediated}}
	if err := Write(dir, files, rows); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "terraform", "x__a.tf")); err != nil {
		t.Error("x__a.tf missing")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "mapping.md"))
	s := string(b)
	if !strings.Contains(s, "NIS2 Art.21(2)(i)") || !strings.Contains(s, "terraform/x__a.tf") {
		t.Errorf("mapping.md lacks article or file:\n%s", s)
	}
}

func TestWriteRefusesPathEscape(t *testing.T) {
	dir := t.TempDir()
	for _, rel := range []string{"../evil.tf", "/abs.tf", "a/../../evil.tf"} {
		err := Write(dir, []render.RenderedFile{{RelPath: rel, Content: "x"}}, nil)
		if err == nil {
			t.Errorf("%q: expected an error", rel)
		}
	}
}

func TestMarkdownCellsAreEscaped(t *testing.T) {
	dir := t.TempDir()
	rows := []SummaryRow{{
		Scanner: "prowler", CheckID: "a|b", ResourceID: "line1\nline2 | x",
		Articles: []string{"p|q"}, Files: []string{"f|g"}, Status: StatusNoMapping, Note: "back\\slash\r\nnext",
	}}
	if err := Write(dir, nil, rows); err != nil {
		t.Fatal(err)
	}
	if err := WriteEvidence(dir, nil, rows, nil); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mapping.md", "evidence.md"} {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		var line string
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "| prowler |") {
				line = l
			}
		}
		if line == "" {
			t.Fatalf("%s: row missing:\n%s", name, b)
		}
		unescaped := strings.ReplaceAll(strings.ReplaceAll(line, "\\\\", ""), "\\|", "")
		cols := strings.Count(unescaped, "|") - 1
		want := 7
		if name == "evidence.md" {
			want = 9
		}
		if cols != want {
			t.Errorf("%s: %d columns, want %d: %s", name, cols, want, line)
		}
		if !strings.Contains(line, `a\|b`) || !strings.Contains(line, "line1 line2") {
			t.Errorf("%s: scanner fields not escaped: %s", name, line)
		}
	}
}

func TestWriteEvidence(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input.json")
	if err := os.WriteFile(in, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	fs := []finding.Finding{{Scanner: "prowler", CheckID: "c", Status: "FAIL", ResourceID: "r"}}
	rows := []SummaryRow{
		{Scanner: "prowler", CheckID: "c", ResourceID: "r", Status: StatusRemediated},
		{Scanner: "prowler", CheckID: "d", ResourceID: "r", Status: StatusNoMapping},
	}
	if err := WriteEvidence(dir, fs, rows, []string{in}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "evidence.md"))
	s := string(b)
	for _, want := range []string{
		"Technical Remediation & Evidence Assistant for NIS2/DORA",
		"risk acceptance remains with the client's management",
		"SHA-256",
		"k8s-remediate-nis2 dev",
		"Remediated: 1",
		"Unmapped: 1",
		"no mapping",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("evidence.md missing %q:\n%s", want, s)
		}
	}
}
