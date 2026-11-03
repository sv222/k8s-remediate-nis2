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

func TestParseASFFProwler5(t *testing.T) {
	fs, err := ParseFormat(read(t, "asff.json"), "asff.json", "asff")
	if err != nil {
		t.Fatal(err)
	}
	if len(fs) != 1 {
		t.Fatalf("findings = %d, want 1", len(fs))
	}
	f := fs[0]
	if f.CheckID != "ec2_ebs_default_encryption" || f.Status != "FAIL" || f.Suppressed || f.AccountID != "000000000000" {
		t.Errorf("finding = %+v", f)
	}
	if f.ResourceID != "000000000000" || f.Region != "us-east-1" || f.Service != "ec2" || f.Severity != "high" {
		t.Errorf("finding fields = %+v", f)
	}
	if !strings.HasPrefix(f.FindingUID, "prowler-ec2_ebs_default_encryption-000000000000-us-east-1-") {
		t.Errorf("finding uid = %q", f.FindingUID)
	}
}

func TestParseASFFStatusAndMuted(t *testing.T) {
	rec := func(status, workflow string) string {
		return `{"SchemaVersion":"2018-10-08","GeneratorId":"prowler-s3_bucket_public_access","AwsAccountId":"1","Compliance":{"Status":"` + status + `"},"Workflow":{"Status":"` + workflow + `"},"Resources":[{"Id":"arn:aws:s3:::b","Region":"eu-west-1"}]}`
	}
	cases := []struct {
		status, workflow, want string
		muted                  bool
	}{
		{"FAILED", "", "FAIL", false},
		{"PASSED", "NEW", "PASS", false},
		{"NOT_AVAILABLE", "", "MANUAL", false},
		{"WARNING", "", "WARNING", true},
		{"FAILED", "SUPPRESSED", "FAIL", true},
	}
	for _, c := range cases {
		fs, err := Parse([]byte("["+rec(c.status, c.workflow)+"]"), "x.json")
		if err != nil {
			t.Fatal(err)
		}
		if f := fs[0]; f.Status != c.want || f.Suppressed != c.muted || f.ResourceID != "b" || f.Region != "eu-west-1" {
			t.Errorf("%s/%s: got %+v", c.status, c.workflow, f)
		}
	}
}

func TestARNName(t *testing.T) {
	cases := map[string]string{
		"arn:aws:s3:::nr-plain": "nr-plain",
		"arn:aws:ec2:us-east-1:000000000000:security-group/sg-0a1b2c":  "sg-0a1b2c",
		"arn:aws:ec2:us-east-1:000000000000:vpc/vpc-0a1b2c":            "vpc-0a1b2c",
		"arn:aws:rds:us-east-1:000000000000:db:nr-db":                  "nr-db",
		"arn:aws:ec2:us-east-1:000000000000:volume":                    "000000000000",
		"arn:aws:iam:us-east-1:000000000000:password-policy":           "000000000000",
		"arn:aws:cloudtrail:us-east-1:000000000000:trail/nr-trail":     "nr-trail",
		"arn:aws-us-gov:eks:us-gov-west-1:000000000000:cluster/nr-eks": "nr-eks",
		"sg-0a1b2c": "sg-0a1b2c",
		"":          "",
	}
	for in, want := range cases {
		if got := arnName(in, "000000000000"); got != want {
			t.Errorf("arnName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseFormatRejectsMismatchAndUnknown(t *testing.T) {
	cases := []struct{ file, format, want string }{
		{"ocsf.json", "asff", "record is ocsf, but --input-format is asff"},
		{"asff.json", "ocsf", "record is asff, but --input-format is ocsf"},
		{"legacy.json", "asff", "record is json, but --input-format is asff"},
		{"ocsf.json", "sarif", "unknown Prowler input format"},
	}
	for _, c := range cases {
		_, err := ParseFormat(read(t, c.file), c.file, c.format)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s as %s: err = %v, want %q", c.file, c.format, err, c.want)
		}
	}
	_, err := Parse([]byte(`[{"SchemaVersion":"2018-10-08","GeneratorId":"aws-foundational-security-best-practices/v/1.0.0/S3.8","Compliance":{"Status":"FAILED"}}]`), "hub.json")
	if err == nil || !strings.Contains(err.Error(), "Prowler GeneratorId") {
		t.Errorf("non-Prowler ASFF: err = %v", err)
	}
}
