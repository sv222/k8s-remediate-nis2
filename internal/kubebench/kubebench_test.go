package kubebench

import (
	"os"
	"testing"
)

func TestParse(t *testing.T) {
	data, _ := os.ReadFile("testdata/bench.json")
	fs, err := Parse(data, "bench.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2", len(fs))
	}
	if fs[0].CheckID != "1.1.12" || fs[0].Status != "FAIL" {
		t.Errorf("first = %+v", fs[0])
	}
	if fs[1].Status != "PASS" {
		t.Errorf("statuses kept verbatim, got %s", fs[1].Status)
	}
}
