package out

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/sv222/k8s-remediate-nis2/internal/render"
)

func report(rows ...SummaryRow) Report {
	return Report{Rows: rows, Inputs: []Input{{Path: "in.json", SHA256: strings.Repeat("a", 64)}}}
}

func TestWriteTree(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "nested", "out")
	files := []render.RenderedFile{
		{RelPath: "terraform/x__a.tf", Content: "x"},
		{RelPath: "kyverno/y.yaml", Content: "y"},
	}
	row := SummaryRow{Scanner: "prowler", CheckID: "c", ResourceID: "r",
		Articles: []string{"NIS2 Art.21(2)(i)"}, Files: []string{"terraform/x__a.tf"}, Status: StatusCodeGenerated}
	if err := Write(dir, false, files, report(row), false); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "terraform", "x__a.tf")); err != nil {
		t.Error("x__a.tf missing")
	}
	b, _ := os.ReadFile(filepath.Join(dir, "mapping.md"))
	s := string(b)
	if !strings.Contains(s, "NIS2 Art.21(2)(i)") || !strings.Contains(s, "`terraform/x__a.tf`") {
		t.Errorf("mapping.md lacks article or file:\n%s", s)
	}
	m, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"terraform/x__a.tf", "mapping.md", "mapping_sha256", "kyverno/y.yaml"} {
		if !strings.Contains(string(m), want) {
			t.Errorf("manifest lacks %q:\n%s", want, m)
		}
	}
}

func TestWriteRefusesPathEscape(t *testing.T) {
	for _, rel := range []string{"../evil.tf", "/abs.tf", "a/../../evil.tf"} {
		dir := t.TempDir()
		err := Write(dir, false, []render.RenderedFile{{RelPath: rel, Content: "x"}}, Report{}, false)
		if err == nil {
			t.Errorf("%q: expected an error", rel)
		}
	}
}

func TestWriteRefusesNonEmptyDirWithoutForce(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "old.tf"), []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, false, nil, Report{}, false); err == nil || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("err = %v, want a --force hint", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "mapping.md")); err == nil {
		t.Error("files were written despite the refusal")
	}
}

func TestForceRemovesOnlyManifestFiles(t *testing.T) {
	dir := t.TempDir()
	first := []render.RenderedFile{{RelPath: "terraform/old__a.tf", Content: "old"}}
	if err := Write(dir, false, first, Report{}, true); err != nil {
		t.Fatal(err)
	}
	mine := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(mine, []byte("mine"), 0o644); err != nil {
		t.Fatal(err)
	}
	second := []render.RenderedFile{{RelPath: "terraform/new__b.tf", Content: "new"}}
	if err := Write(dir, true, second, Report{}, false); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{"terraform/old__a.tf", "evidence.md"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(gone))); err == nil {
			t.Errorf("stale %s was not removed", gone)
		}
	}
	for _, kept := range []string{"terraform/new__b.tf", "notes.txt", "mapping.md", ManifestName} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(kept))); err != nil {
			t.Errorf("%s is missing: %v", kept, err)
		}
	}
}

func TestForceRejectsManifestWithEscapingPath(t *testing.T) {
	dir := t.TempDir()
	victim := filepath.Join(filepath.Dir(dir), "victim.txt")
	if err := os.WriteFile(victim, []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(victim)
	m := `{"files":[{"path":"../victim.txt","sha256":"x"}]}`
	if err := os.WriteFile(filepath.Join(dir, ManifestName), []byte(m), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := Write(dir, true, nil, Report{}, false); err == nil {
		t.Error("expected an error")
	}
	if _, err := os.Stat(victim); err != nil {
		t.Error("a file outside the output directory was removed")
	}
}

func TestCodeSpansNeutralizeMarkdown(t *testing.T) {
	cases := []string{
		"![x](https://attacker.example/p.png)",
		"a`b",
		"line1\nline2 | x",
		"<script>",
		"[link](javascript:alert(1))",
		"**bold**",
		"back\\slash",
	}
	for _, in := range cases {
		got := code(in)
		inner := strings.Trim(got, "`")
		if strings.ContainsAny(inner, "`|\n\r<>[]()!* \\") {
			t.Errorf("code(%q) = %q keeps a special character", in, got)
		}
	}
	if code("") != "" {
		t.Error("empty input must give an empty cell")
	}
	if got := code("s3_bucket.name-1:/@+=,"); got != "`s3_bucket.name-1:/@+=,`" {
		t.Errorf("a valid token changed: %q", got)
	}
}

func TestCellEscapesMarkdownSyntax(t *testing.T) {
	got := cell("![x](https://a/p.png) `c` *b* a|b <i> \\ x\ny")
	for _, bad := range []string{"![", "<i>", "\n", " |b"} {
		if strings.Contains(got, bad) {
			t.Errorf("cell output keeps %q: %q", bad, got)
		}
	}
	if !strings.Contains(got, "\\[x\\]") || !strings.Contains(got, "a\\|b") {
		t.Errorf("brackets or pipe not escaped: %q", got)
	}
}

func TestRowsKeepColumnCountWithHostileInput(t *testing.T) {
	dir := t.TempDir()
	row := SummaryRow{
		Scanner: "prowler", CheckID: "a|b", ResourceID: "line1\nline2 | x ![x](https://attacker.example/p.png)",
		Articles: []string{"p|q"}, Files: []string{"f|g"}, Status: StatusNoMapping, Note: "back\\slash\r\nnext", Region: "r|s", Account: "a|b",
	}
	if err := Write(dir, false, nil, report(row), true); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mapping.md", "evidence.md"} {
		b, _ := os.ReadFile(filepath.Join(dir, name))
		var line string
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "| `prowler` |") {
				line = l
			}
		}
		if line == "" {
			t.Fatalf("%s: row missing:\n%s", name, b)
		}
		unescaped := strings.ReplaceAll(strings.ReplaceAll(line, "\\\\", ""), "\\|", "")
		want := 7
		if name == "evidence.md" {
			want = 10
		}
		if cols := strings.Count(unescaped, "|") - 1; cols != want {
			t.Errorf("%s: %d columns, want %d: %s", name, cols, want, line)
		}
		if strings.Contains(line, "![") || strings.Contains(line, "](") {
			t.Errorf("%s: markdown image or link survived: %s", name, line)
		}
	}
}

func TestEvidenceStatesNothingIsApplied(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "input.json")
	if err := os.WriteFile(in, []byte("[]"), 0o644); err != nil {
		t.Fatal(err)
	}
	rep := Report{
		Rows: []SummaryRow{
			{Scanner: "prowler", CheckID: "c", ResourceID: "r", Status: StatusCodeGenerated},
			{Scanner: "prowler", CheckID: "d", ResourceID: "r", Status: StatusNoMapping},
			{Scanner: "prowler", CheckID: "e", ResourceID: "r", Status: StatusFollowUp, Note: "open item"},
		},
		Stats:      Stats{Records: 9, Failed: 3, Passed: 2, Manual: 1, Suppressed: 1, Duplicates: 2},
		Inputs:     []Input{{Path: in, SHA256: strings.Repeat("b", 64)}},
		Accounts:   []string{"000000000000"},
		Manual:     []Item{{Scanner: "prowler", CheckID: "m", ResourceID: "r", Status: "MANUAL"}},
		Suppressed: []Item{{Scanner: "prowler", CheckID: "s", ResourceID: "r", Status: "FAIL"}},
	}
	files := []render.RenderedFile{{RelPath: "terraform/x.tf", Content: "x"}}
	out := filepath.Join(dir, "out")
	if err := Write(out, false, files, rep, true); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(out, "evidence.md"))
	s := string(b)
	for _, want := range []string{
		"Technical Remediation & Evidence Assistant for NIS2/DORA",
		"risk acceptance remains with the client's management",
		"Nothing in this report was applied",
		"SHA-256 of the exact bytes that were parsed",
		"Generated (UTC)",
		"Mapping: version",
		"Failed findings (FAIL): 3",
		"Passed: 2",
		"Suppressed (muted): 1",
		"Duplicate records ignored: 2",
		"code generated: 1 | follow-up required: 1 | guidance only: 0 | no mapping: 1 | skipped: 0",
		"`000000000000`",
		"Manual or not assessed by the scanner",
		"Suppressed (muted) findings, not remediated",
		"`terraform/x.tf` - SHA-256",
		"open item",
	} {
		if !strings.Contains(s, want) {
			t.Errorf("evidence.md missing %q:\n%s", want, s)
		}
	}
	if strings.Contains(s, "Remediated:") {
		t.Error("evidence.md must not use the word Remediated as a count")
	}
}

func TestEvidenceTimestampIsUTC(t *testing.T) {
	zone := time.FixedZone("x", 5*3600)
	s := evidenceMD(nil, Report{}, time.Date(2026, 1, 2, 3, 4, 5, 0, zone))
	if !strings.Contains(s, "2026-01-01T22:04:05Z") {
		t.Errorf("timestamp is not UTC:\n%s", s)
	}
}

var testTime = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
