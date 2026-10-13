package kubebench

import (
	"os"
	"testing"

	"github.com/sv222/k8s-remediate-nis2/internal/finding"
)

func byID(fs []finding.Finding) map[string]finding.Finding {
	m := map[string]finding.Finding{}
	for _, f := range fs {
		m[f.CheckID] = f
	}
	return m
}

func TestParseRealKubeBench016(t *testing.T) {
	data, err := os.ReadFile("testdata/bench.json")
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Parse(data, "bench.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 131 {
		t.Fatalf("findings = %d, want 131", len(fs))
	}
	counts := map[string]int{}
	for _, f := range fs {
		counts[f.Status]++
		if f.Benchmark != "cis-1.12" || f.Scanner != "kube-bench" || f.ResourceID != "cluster" {
			t.Fatalf("unexpected finding %+v", f)
		}
	}
	if counts["PASS"] != 63 || counts["FAIL"] != 12 || counts["WARN"] != 56 || counts["INFO"] != 0 {
		t.Errorf("status counts = %v, want PASS 63, FAIL 12, WARN 56", counts)
	}
	m := byID(fs)
	if f := m["1.1.12"]; f.Status != "FAIL" || f.Manual || f.IsManualWarn() {
		t.Errorf("1.1.12 = %+v", f)
	}
	for _, id := range []string{"5.2.2", "5.2.5", "5.2.7"} {
		if f := m[id]; f.Status != "WARN" || !f.Manual || !f.IsManualWarn() {
			t.Errorf("%s must parse as manual WARN: %+v", id, f)
		}
	}
	if f := m["1.1.1"]; f.Status != "PASS" || f.Manual {
		t.Errorf("1.1.1 = %+v", f)
	}
}

func TestParseBareArray(t *testing.T) {
	data := []byte(`[{"id":"4","version":"eks-1.2.0","tests":[{"section":"4.2","results":[{"test_number":"4.2.1","status":"fail","test_desc":"x"}]}]}]`)
	fs, err := Parse(data, "bare.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 || fs[0].Benchmark != "eks-1.2.0" || fs[0].Status != "FAIL" {
		t.Errorf("findings = %+v", fs)
	}
}

func TestIsManual(t *testing.T) {
	cases := []struct {
		typ, desc string
		want      bool
	}{
		{"manual", "Minimize the admission of root containers (Manual)", true},
		{"", "Minimize the admission of privileged containers (Manual)", true},
		{"", "Minimize the admission of privileged containers (Not Scored)", true},
		{"MANUAL", "x", true},
		{"", "Minimize the admission of containers wishing to share the host network namespace (Scored)", false},
		{"", "Ensure that the etcd data directory ownership is set to etcd:etcd (Automated)", false},
		{"", "", false},
	}
	for _, c := range cases {
		if got := isManual(c.typ, c.desc); got != c.want {
			t.Errorf("isManual(%q, %q) = %v, want %v", c.typ, c.desc, got, c.want)
		}
	}
}

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "{}", `{"Controls":[]}`, "not json"} {
		if _, err := Parse([]byte(in), "x.json"); err == nil {
			t.Errorf("input %q: expected an error", in)
		}
	}
}
