package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type rec struct {
	check, status, resource, region, account string
	muted                                    bool
}

func legacyJSON(recs ...rec) string {
	var parts []string
	for _, r := range recs {
		region := r.region
		if region == "" {
			region = "us-east-1"
		}
		b, _ := json.Marshal(map[string]any{
			"FindingUniqueId": "uid-" + r.check + "-" + r.resource, "CheckID": r.check, "Status": r.status,
			"ResourceId": r.resource, "Region": region, "AccountId": r.account, "Severity": "high", "Muted": r.muted,
		})
		parts = append(parts, string(b))
	}
	return "[" + strings.Join(parts, ",") + "]"
}

func ocsfJSON(check, status, resource string, statusID int, statusLabel string) string {
	b, _ := json.Marshal([]map[string]any{{
		"metadata":     map[string]any{"event_code": check},
		"status":       statusLabel,
		"status_id":    statusID,
		"status_code":  status,
		"severity":     "High",
		"finding_info": map[string]any{"uid": "u-" + check, "title": "t", "desc": "d"},
		"resources":    []map[string]any{{"name": resource, "uid": resource, "region": "us-east-1", "group": map[string]any{"name": "s3"}}},
		"cloud":        map[string]any{"region": "us-east-1", "account": map[string]any{"uid": "111111111111"}},
	}})
	return string(b)
}

func runWith(t *testing.T, input string, extra ...string) (string, map[string]string, error) {
	t.Helper()
	dir := t.TempDir()
	in := filepath.Join(dir, "in.json")
	if err := os.WriteFile(in, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	msg, err := execute(t, append([]string{"remediate", "--prowler", in, "--out", out}, extra...)...)
	if err != nil {
		return msg, nil, err
	}
	return msg, tree(t, out), nil
}

const (
	checkSSH = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_22"
	checkRDP = "ec2_securitygroup_allow_ingress_from_internet_to_tcp_port_3389"
)

func TestSecurityGroupsNeverGainPortsTheyWereNotFlaggedFor(t *testing.T) {
	_, files, err := runWith(t, legacyJSON(
		rec{check: checkRDP, status: "FAIL", resource: "sg-aaaa"},
		rec{check: checkSSH, status: "FAIL", resource: "sg-bbbb"},
	))
	if err != nil {
		t.Fatal(err)
	}
	a := files["terraform/sg_restrict_rdp__sg-aaaa.tf"]
	b := files["terraform/sg_restrict_ssh__sg-bbbb.tf"]
	if !strings.Contains(a, "from_port         = 3389") || strings.Contains(a, "from_port         = 22") {
		t.Errorf("sg-aaaa rule wrong:\n%s", a)
	}
	if !strings.Contains(b, "from_port         = 22") {
		t.Errorf("sg-bbbb rule wrong:\n%s", b)
	}
	for rel := range files {
		if strings.Contains(rel, "sg_restrict_ssh__sg-aaaa") || strings.Contains(rel, "sg_restrict_rdp__sg-bbbb") {
			t.Errorf("unexpected file %s", rel)
		}
		if strings.HasSuffix(rel, ".tf") && (strings.Contains(files[rel], "allowed_port") || strings.Contains(files[rel], "var.allowed_cidr")) {
			t.Errorf("%s still uses the shared variables", rel)
		}
	}
	if !strings.Contains(files["mapping.md"], "follow-up required") {
		t.Error("security group rows must be follow-up required")
	}
}

func TestSuppressedFindingsAreCountedNotRemediated(t *testing.T) {
	input := legacyJSON(
		rec{check: "s3_bucket_level_public_access_block", status: "FAIL", resource: "muted-bucket", muted: true},
		rec{check: "s3_bucket_level_public_access_block", status: "FAIL", resource: "live-bucket"},
	)
	_, files, err := runWith(t, input, "--export-evidence")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["terraform/s3_public_access_block__muted-bucket.tf"]; ok {
		t.Error("a muted finding was remediated")
	}
	if _, ok := files["terraform/s3_public_access_block__live-bucket.tf"]; !ok {
		t.Error("the live finding was not remediated")
	}
	ev := files["evidence.md"]
	if !strings.Contains(ev, "Suppressed (muted): 1") || !strings.Contains(ev, "Suppressed (muted) findings, not remediated") || !strings.Contains(ev, "`muted-bucket`") {
		t.Errorf("suppressed finding not reported:\n%s", ev)
	}
}

func TestOCSFSuppressedStatusIsHonored(t *testing.T) {
	for _, tc := range []struct {
		id    int
		label string
		want  bool
	}{{3, "Suppressed", true}, {1, "New", false}, {0, "suppressed", true}} {
		_, files, err := runWith(t, ocsfJSON("s3_bucket_level_public_access_block", "FAIL", "some-bucket", tc.id, tc.label))
		if err != nil {
			t.Fatal(err)
		}
		_, has := files["terraform/s3_public_access_block__some-bucket.tf"]
		if has == tc.want {
			t.Errorf("status %d/%s: file present = %v, want %v", tc.id, tc.label, has, !tc.want)
		}
	}
}

func TestMixedAccountsAreRefused(t *testing.T) {
	_, _, err := runWith(t, legacyJSON(
		rec{check: "s3_bucket_level_public_access_block", status: "FAIL", resource: "b1", account: "111111111111"},
		rec{check: "s3_bucket_level_public_access_block", status: "FAIL", resource: "b2", account: "222222222222"},
	))
	if err == nil || !strings.Contains(err.Error(), "111111111111") || !strings.Contains(err.Error(), "222222222222") {
		t.Fatalf("err = %v, want both accounts named", err)
	}
}

func TestAccountAppearsInEvidence(t *testing.T) {
	_, files, err := runWith(t, legacyJSON(rec{check: "s3_bucket_level_public_access_block", status: "FAIL", resource: "b1", account: "111111111111"}), "--export-evidence")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files["evidence.md"], "`111111111111`") {
		t.Errorf("account missing:\n%s", files["evidence.md"])
	}
}

func TestManualDuplicatePassAndOtherAreSeparated(t *testing.T) {
	input := legacyJSON(
		rec{check: "iam_root_mfa_enabled", status: "FAIL", resource: "root"},
		rec{check: "iam_root_mfa_enabled", status: "FAIL", resource: "root"},
		rec{check: "cloudtrail_enabled", status: "MANUAL", resource: "trail"},
		rec{check: "x", status: "PASS", resource: "y"},
		rec{check: "z", status: "INFO", resource: "y"},
	)
	_, files, err := runWith(t, input, "--export-evidence")
	if err != nil {
		t.Fatal(err)
	}
	ev := files["evidence.md"]
	for _, want := range []string{
		"Records read: 5", "Failed findings (FAIL): 1", "Passed: 1", "Manual or not assessed: 1", "Other status: 1", "Duplicate records ignored: 1",
		"`cloudtrail_enabled`",
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence lacks %q:\n%s", want, ev)
		}
	}
	if strings.Count(files["mapping.md"], "iam_root_mfa_enabled") != 1 {
		t.Errorf("duplicate row listed twice:\n%s", files["mapping.md"])
	}
}

func TestOutputDirectoryMustBeEmptyUnlessForced(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "in.json")
	input := legacyJSON(rec{check: "s3_bucket_level_public_access_block", status: "FAIL", resource: "bucket-one"})
	if err := os.WriteFile(in, []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if _, err := execute(t, "remediate", "--prowler", in, "--out", out, "--export-evidence"); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(t, "remediate", "--prowler", in, "--out", out); err == nil {
		t.Fatal("a second run into a non-empty directory must fail")
	}
	input2 := legacyJSON(rec{check: "s3_bucket_level_public_access_block", status: "FAIL", resource: "bucket-two"})
	if err := os.WriteFile(in, []byte(input2), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := execute(t, "remediate", "--prowler", in, "--out", out, "--force"); err != nil {
		t.Fatal(err)
	}
	files := tree(t, out)
	if _, ok := files["terraform/s3_public_access_block__bucket-one.tf"]; ok {
		t.Error("stale Terraform file of the first run is still there")
	}
	if _, ok := files["evidence.md"]; ok {
		t.Error("stale evidence.md of the first run is still there")
	}
	if _, ok := files["terraform/s3_public_access_block__bucket-two.tf"]; !ok {
		t.Error("new file missing")
	}
}

func TestEncryptionSnippetsDoNotConflictOnOneBucket(t *testing.T) {
	_, files, err := runWith(t, legacyJSON(
		rec{check: "s3_bucket_default_encryption", status: "FAIL", resource: "bucket-one"},
		rec{check: "s3_bucket_kms_encryption", status: "FAIL", resource: "bucket-one"},
		rec{check: "s3_bucket_default_encryption", status: "FAIL", resource: "bucket-two"},
	))
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := files["terraform/s3_encryption__bucket-one.tf"]; ok {
		t.Error("the AES256 file was written next to the KMS file for the same bucket")
	}
	if _, ok := files["terraform/s3_encryption_kms__bucket-one.tf"]; !ok {
		t.Error("the KMS file is missing")
	}
	if _, ok := files["terraform/s3_encryption__bucket-two.tf"]; !ok {
		t.Error("the AES256 file of the other bucket is missing")
	}
	if !strings.Contains(files["mapping.md"], "Superseded") {
		t.Errorf("the skipped row is not explained:\n%s", files["mapping.md"])
	}
}

func TestHostileIDsCannotInjectMarkdown(t *testing.T) {
	hostile := "![x](https://attacker.example/p.png)"
	_, files, err := runWith(t, legacyJSON(rec{check: "iam_root_mfa_enabled", status: "FAIL", resource: hostile}), "--export-evidence")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mapping.md", "evidence.md"} {
		if strings.Contains(files[name], "![") || strings.Contains(files[name], "](") {
			t.Errorf("%s contains the hostile id:\n%s", name, files[name])
		}
		if !strings.Contains(files[name], "unsupported characters") {
			t.Errorf("%s does not flag the bad id", name)
		}
	}
}

func TestEvidenceHashesMatchTheParsedBytesAndGeneratedFiles(t *testing.T) {
	input := legacyJSON(rec{check: "s3_bucket_level_public_access_block", status: "FAIL", resource: "bucket-one"})
	_, files, err := runWith(t, input, "--export-evidence")
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(input))
	ev := files["evidence.md"]
	if !strings.Contains(ev, hex.EncodeToString(sum[:])) {
		t.Errorf("input hash missing:\n%s", ev)
	}
	tf := files["terraform/s3_public_access_block__bucket-one.tf"]
	fsum := sha256.Sum256([]byte(tf))
	if !strings.Contains(ev, hex.EncodeToString(fsum[:])) {
		t.Errorf("generated file hash missing:\n%s", ev)
	}
	var m struct {
		Version string `json:"version"`
		Files   []struct {
			Path   string `json:"path"`
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	if err := json.Unmarshal([]byte(files["manifest.json"]), &m); err != nil {
		t.Fatal(err)
	}
	for _, f := range m.Files {
		got := sha256.Sum256([]byte(files[f.Path]))
		if f.Path != "evidence.md" && hex.EncodeToString(got[:]) != f.SHA256 {
			t.Errorf("manifest hash of %s is wrong", f.Path)
		}
	}
	if m.Version == "" {
		t.Error("manifest has no tool version")
	}
}

func TestEvidenceDoesNotCountFilesAsRemediated(t *testing.T) {
	_, files, err := runWith(t, legacyJSON(rec{check: "s3_bucket_level_public_access_block", status: "FAIL", resource: "bucket-one"}), "--export-evidence")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"mapping.md", "evidence.md"} {
		if strings.Contains(strings.ToLower(files[name]), "remediated:") || strings.Contains(files[name], "| remediated |") {
			t.Errorf("%s still counts written files as remediated", name)
		}
	}
	if !strings.Contains(files["evidence.md"], "Nothing in this report was applied") {
		t.Error("evidence.md does not say that nothing was applied")
	}
}

func TestAllKubernetesPoliciesCoverEphemeralContainers(t *testing.T) {
	out := filepath.Join(t.TempDir(), "o")
	if _, err := execute(t, "remediate", "--kube-bench", "testdata/kube_bench.json", "--out", out); err != nil {
		t.Fatal(err)
	}
	files := tree(t, out)
	for _, rel := range []string{"kyverno/block_privileged.yaml", "kyverno/require_nonroot.yaml"} {
		if !strings.Contains(files[rel], "pods/ephemeralcontainers") {
			t.Errorf("%s does not match the ephemeralcontainers subresource", rel)
		}
	}
}
