package prowler

import (
	"os"
	"strings"
	"testing"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestParseLegacy(t *testing.T) {
	fs, err := Parse(read(t, "legacy.json"), "legacy.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 {
		t.Fatalf("findings = %d, want 3", len(fs))
	}
	f := fs[0]
	if f.Scanner != "prowler" || f.CheckID != "s3_bucket_level_public_access_block" || f.Status != "FAIL" {
		t.Errorf("first finding = %+v", f)
	}
	if f.ResourceID != "company-frontend-assets" || f.Region != "eu-central-1" || f.Service != "s3" || f.Severity != "medium" {
		t.Errorf("first finding fields = %+v", f)
	}
	if !strings.HasPrefix(f.FindingUID, "prowler-aws-s3_bucket_level_public_access_block") {
		t.Errorf("finding uid = %q", f.FindingUID)
	}
	if fs[1].ResourceID != "sg-0a1b2c3d4e5f60718" || fs[1].Severity != "high" {
		t.Errorf("second finding = %+v", fs[1])
	}
	if fs[2].Status != "PASS" {
		t.Errorf("third status = %s", fs[2].Status)
	}
}

func TestParseOCSF(t *testing.T) {
	fs, err := Parse(read(t, "ocsf.json"), "ocsf.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 3 {
		t.Fatalf("findings = %d, want 3", len(fs))
	}
	f := fs[0]
	if f.CheckID != "s3_bucket_level_public_access_block" || f.Status != "FAIL" {
		t.Errorf("first finding = %+v", f)
	}
	if f.ResourceID != "company-frontend-assets" || f.Region != "eu-central-1" || f.Service != "s3" || f.Severity != "medium" {
		t.Errorf("first finding fields = %+v", f)
	}
	if fs[1].CheckID != "ec2_securitygroup_allow_ingress_from_internet_to_any_port" || fs[1].ResourceID != "sg-0a1b2c3d4e5f60718" {
		t.Errorf("second finding = %+v", fs[1])
	}
	if fs[2].Status != "PASS" {
		t.Errorf("third status = %s", fs[2].Status)
	}
}

func TestParseLegacyAndOCSFAgree(t *testing.T) {
	a, err := Parse(read(t, "legacy.json"), "legacy.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(read(t, "ocsf.json"), "ocsf.json")
	if err != nil {
		t.Fatal(err)
	}
	for i := range a {
		if a[i].CheckID != b[i].CheckID || a[i].Status != b[i].Status || a[i].ResourceID != b[i].ResourceID || a[i].FindingUID != b[i].FindingUID {
			t.Errorf("record %d differs: %+v vs %+v", i, a[i], b[i])
		}
	}
}

func TestParseRejectsUnsupportedLayouts(t *testing.T) {
	cases := map[string]string{
		"asff.json":                  "json-asff",
		"object_wrapper.json":        "unsupported Prowler layout",
		"legacy_missing_status.json": "without CheckID or Status",
	}
	for name, want := range cases {
		_, err := Parse(read(t, name), name)
		if err == nil {
			t.Errorf("%s: expected an error", name)
			continue
		}
		if !strings.Contains(err.Error(), want) {
			t.Errorf("%s: error %q lacks %q", name, err, want)
		}
	}
}

func TestParseRejectsEmptyAndGarbage(t *testing.T) {
	for _, in := range []string{"", "   ", "[]", "[1,2]", "[{}]", "[null]", "not json"} {
		if _, err := Parse([]byte(in), "x.json"); err == nil {
			t.Errorf("input %q: expected an error", in)
		}
	}
}
