package prowler

import (
	"os"
	"testing"
)

func TestParseV4(t *testing.T) {
	data, _ := os.ReadFile("testdata/v4.json")
	fs, err := Parse(data, "v4.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 2 {
		t.Fatalf("findings = %d, want 2", len(fs))
	}
	if fs[0].CheckID != "s3_bucket_public_access_block" || fs[0].Scanner != "prowler" {
		t.Errorf("first finding = %+v", fs[0])
	}
	if fs[1].Status != "PASS" {
		t.Errorf("status kept verbatim, got %s", fs[1].Status)
	}
}

func TestParseV3Rejected(t *testing.T) {
	data, _ := os.ReadFile("testdata/v3.json")
	_, err := Parse(data, "v3.json")
	if err == nil {
		t.Fatal("v3 layout must be rejected with a version error")
	}
}
