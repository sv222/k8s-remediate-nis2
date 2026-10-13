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

func TestParseLegacyProwler3(t *testing.T) {
	fs, err := Parse(read(t, "legacy.json"), "legacy.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 7 {
		t.Fatalf("findings = %d, want 7", len(fs))
	}
	f := fs[0]
	if f.Scanner != "prowler" || f.CheckID != "s3_bucket_level_public_access_block" || f.Status != "FAIL" {
		t.Errorf("first finding = %+v", f)
	}
	if f.ResourceID != "acme-customer-exports" || f.Region != "us-east-1" || f.Service != "s3" || f.Severity != "medium" {
		t.Errorf("first finding fields = %+v", f)
	}
	if !strings.HasPrefix(f.FindingUID, "prowler-aws-s3_bucket_level_public_access_block") {
		t.Errorf("finding uid = %q", f.FindingUID)
	}
	if fs[4].CheckID != "ec2_securitygroup_allow_ingress_from_internet_to_any_port" || fs[4].ResourceID != "sg-a899c3f6063affe1f" || fs[4].Severity != "high" {
		t.Errorf("security group finding = %+v", fs[4])
	}
	if fs[6].Status != "PASS" {
		t.Errorf("last status = %s", fs[6].Status)
	}
}

func TestParseOCSFProwler5(t *testing.T) {
	fs, err := Parse(read(t, "ocsf.json"), "ocsf.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 12 {
		t.Fatalf("findings = %d, want 12", len(fs))
	}
	f := fs[0]
	if f.CheckID != "s3_bucket_level_public_access_block" || f.Status != "FAIL" {
		t.Errorf("first finding = %+v", f)
	}
	if f.ResourceID != "acme-customer-exports" || f.Region != "us-east-1" || f.Service != "s3" || f.Severity != "high" {
		t.Errorf("first finding fields = %+v", f)
	}
	if fs[6].CheckID != "ec2_securitygroup_allow_ingress_from_internet_to_all_ports" || fs[6].ResourceID != "sg-1534e2968c20202a0" {
		t.Errorf("security group finding = %+v", fs[6])
	}
	if fs[8].CheckID != "eks_cluster_not_publicly_accessible" || fs[8].ResourceID != "acme-eks" || fs[8].Service != "eks" {
		t.Errorf("eks finding = %+v", fs[8])
	}
	if fs[11].Status != "PASS" {
		t.Errorf("last status = %s", fs[11].Status)
	}
}

func TestParseLegacyAndOCSFAgreeOnSameResources(t *testing.T) {
	a, err := Parse(read(t, "legacy.json"), "legacy.json")
	if err != nil {
		t.Fatal(err)
	}
	b, err := Parse(read(t, "ocsf.json"), "ocsf.json")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if a[i].CheckID != b[i].CheckID || a[i].Status != b[i].Status || a[i].ResourceID != b[i].ResourceID ||
			a[i].FindingUID != b[i].FindingUID || a[i].Region != b[i].Region || a[i].Service != b[i].Service {
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
