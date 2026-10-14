package mapping

import (
	"io/fs"
	"os"
	"strings"
	"testing"

	"github.com/sv222/k8s-remediate-nis2/internal/finding"
)

func TestLoadAndLookup(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) < 8 {
		t.Fatalf("entries = %d, want >= 8", len(entries))
	}
	e, ok, err := For(finding.Finding{Scanner: "prowler", CheckID: "s3_bucket_level_public_access_block"})
	if err != nil || !ok || len(e.Templates) != 1 || e.Templates[0] != "terraform/s3_public_access_block.tf" {
		t.Errorf("lookup failed: %+v ok=%v err=%v", e, ok, err)
	}
}

func TestLookupMissesObsoleteAndUnknown(t *testing.T) {
	for _, id := range []string{"awsv526", "ec2_security_group_ingress_open_to_internet", "unknown"} {
		_, ok, err := For(finding.Finding{Scanner: "prowler", CheckID: id})
		if err != nil || ok {
			t.Errorf("%s: ok=%v err=%v, want no mapping", id, ok, err)
		}
	}
}

func TestKubeBenchLookupIsVersionAware(t *testing.T) {
	cases := []struct {
		bench, id, title string
		ok               bool
	}{
		{"cis-1.8", "5.2.2", "Privileged", true},
		{"cis-1.6", "5.2.1", "Privileged", true},
		{"eks-1.2.0", "4.2.1", "Privileged", true},
		{"cis-1.8", "5.2.5", "host network", true},
		{"cis-1.6", "5.2.4", "host network", true},
		{"cis-1.8", "5.2.7", "Root", true},
		{"eks-1.2.0", "4.2.6", "Root", true},
		{"cis-1.6", "5.2.2", "", false},
		{"cis-1.8", "1.1.12", "", false},
		{"", "5.2.2", "", false},
		{"cis-9.9", "5.2.2", "", false},
	}
	for _, c := range cases {
		e, ok, err := For(finding.Finding{Scanner: "kube-bench", CheckID: c.id, Benchmark: c.bench})
		if err != nil {
			t.Fatal(err)
		}
		if ok != c.ok {
			t.Errorf("%s %s: ok=%v, want %v", c.bench, c.id, ok, c.ok)
			continue
		}
		if ok && !strings.Contains(e.Title, c.title) {
			t.Errorf("%s %s: title %q lacks %q", c.bench, c.id, e.Title, c.title)
		}
	}
}

func TestArticlesUseDirectiveLetters(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		for _, a := range e.Articles {
			if strings.HasPrefix(a, "NIS2 Art.21(2)(") {
				letter := strings.TrimSuffix(strings.TrimPrefix(a, "NIS2 Art.21(2)("), ")")
				if len(letter) != 1 || letter[0] < 'a' || letter[0] > 'j' {
					t.Errorf("%s: bad NIS2 letter in %q", e.Title, a)
				}
			}
		}
	}
}

func TestTemplateCoverage(t *testing.T) {
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	used := map[string]bool{"terraform/versions.tf": true}
	for _, e := range entries {
		for _, tpl := range append(append([]string{}, e.Templates...), e.SharedTemplates...) {
			used[tpl] = true
			if _, err := TemplatesFS.ReadFile("templates/" + tpl); err != nil {
				t.Errorf("entry %s references missing template %s", e.Title, tpl)
			}
		}
	}
	err = fs.WalkDir(TemplatesFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel := strings.TrimPrefix(p, "templates/")
		if !used[rel] {
			t.Errorf("template %s is not referenced by any mapping entry", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsBadEntries(t *testing.T) {
	bad := [][]Entry{
		{{Scanner: "prowler", Articles: []string{"a"}, Guidance: "g"}},
		{{Scanner: "prowler", CheckID: "x", Guidance: "g"}},
		{{Scanner: "prowler", CheckID: "x", Articles: []string{"a"}}},
		{{Scanner: "kube-bench", Articles: []string{"a"}, Guidance: "g"}},
		{{Scanner: "other", CheckID: "x", Articles: []string{"a"}, Guidance: "g"}},
		{
			{Scanner: "prowler", CheckID: "x", Articles: []string{"a"}, Guidance: "g"},
			{Scanner: "prowler", CheckID: "x", Articles: []string{"a"}, Guidance: "g"},
		},
	}
	for i, entries := range bad {
		if err := validate(entries); err == nil {
			t.Errorf("case %d: expected a validation error", i)
		}
	}
}

func TestProwlerCheckIDsExistInProwler5(t *testing.T) {
	data, err := os.ReadFile("testdata/prowler_5.45.0_checks.txt")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, id := range strings.Fields(string(data)) {
		known[id] = true
	}
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Scanner == "prowler" && !known[e.CheckID] {
			t.Errorf("check %s is not in `prowler aws --list-checks` of Prowler 5.45.0", e.CheckID)
		}
	}
}

func TestKubeBenchIDsMatchKubeBenchConfig(t *testing.T) {
	data, err := os.ReadFile("testdata/kube_bench_0.16.0_ids.tsv")
	if err != nil {
		t.Fatal(err)
	}
	real := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		real[line] = true
	}
	entries, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Scanner != "kube-bench" {
			continue
		}
		var role string
		switch {
		case strings.Contains(e.Title, "Privileged"):
			role = "privileged"
		case strings.Contains(e.Title, "host network"):
			role = "hostnet"
		case strings.Contains(e.Title, "Root"):
			role = "root"
		default:
			t.Fatalf("entry %q has no known role", e.Title)
		}
		for bench, id := range e.BenchmarkIDs {
			if !real[bench+"\t"+role+"\t"+id] {
				t.Errorf("%s %s (%s) is not in the kube-bench 0.16.0 config", bench, id, role)
			}
		}
	}
}

func TestKubeBenchCoversCurrentBenchmarks(t *testing.T) {
	for _, bench := range []string{"cis-1.7", "cis-1.8", "cis-1.9", "cis-1.10", "cis-1.11", "cis-1.12", "eks-1.5.0", "eks-1.7.0", "eks-1.8.0"} {
		_, ok, err := For(finding.Finding{Scanner: "kube-bench", CheckID: "5.2.2", Benchmark: bench})
		if bench[:3] == "eks" {
			_, ok, err = For(finding.Finding{Scanner: "kube-bench", CheckID: "4.2.1", Benchmark: bench})
		}
		if err != nil || !ok {
			t.Errorf("%s: privileged control not mapped (ok=%v err=%v)", bench, ok, err)
		}
	}
}

func TestKubeBenchMappingCoversEveryConfigRow(t *testing.T) {
	data, err := os.ReadFile("testdata/kube_bench_0.16.0_ids.tsv")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(data)), "\n") {
		cols := strings.Split(line, "\t")
		if len(cols) != 3 {
			t.Fatalf("bad row %q", line)
		}
		_, ok, err := For(finding.Finding{Scanner: "kube-bench", CheckID: cols[2], Benchmark: cols[0]})
		if err != nil || !ok {
			t.Errorf("%s %s (%s) from the kube-bench 0.16.0 config is not mapped", cols[0], cols[2], cols[1])
		}
	}
}
