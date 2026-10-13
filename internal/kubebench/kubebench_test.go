package kubebench

import (
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	data, err := os.ReadFile("testdata/bench.json")
	if err != nil {
		t.Fatal(err)
	}
	fs, err := Parse(data, "bench.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 5 {
		t.Fatalf("findings = %d, want 5", len(fs))
	}
	if fs[0].CheckID != "1.1.12" || fs[0].Status != "FAIL" || fs[0].Benchmark != "cis-1.8" {
		t.Errorf("first = %+v", fs[0])
	}
	if fs[1].Status != "PASS" {
		t.Errorf("statuses kept, got %s", fs[1].Status)
	}
	if fs[2].CheckID != "5.2.2" || fs[2].Benchmark != "cis-1.8" || fs[2].ResourceID != "cluster" {
		t.Errorf("third = %+v", fs[2])
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

func TestParseRejects(t *testing.T) {
	for _, in := range []string{"", "{}", `{"Controls":[]}`, "not json"} {
		if _, err := Parse([]byte(in), "x.json"); err == nil {
			t.Errorf("input %q: expected an error", in)
		}
	}
}
