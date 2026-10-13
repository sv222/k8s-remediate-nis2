package cmd

import (
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := NewRootCmd()
	var buf bytes.Buffer
	root.SetOut(&buf)
	root.SetErr(&buf)
	root.SetArgs(args)
	err := root.Execute()
	return buf.String(), err
}

func tree(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		files[filepath.ToSlash(rel)] = string(b)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func TestGolden(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{"legacy_and_bench", []string{"--prowler", "testdata/prowler_legacy.json", "--kube-bench", "testdata/kube_bench.json"}},
		{"ocsf_only", []string{"--prowler", "testdata/prowler_ocsf.json"}},
		{"two_buckets", []string{"--prowler", "testdata/prowler_two_buckets.json"}},
		{"aws_gaps", []string{"--prowler", "testdata/prowler_aws_gaps.json"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			out := filepath.Join(t.TempDir(), "remediation")
			if _, err := execute(t, append([]string{"remediate", "--out", out}, c.args...)...); err != nil {
				t.Fatal(err)
			}
			got := tree(t, out)
			golden := filepath.Join("testdata", "golden", c.name)
			if os.Getenv("UPDATE_GOLDEN") != "" {
				if err := os.RemoveAll(golden); err != nil {
					t.Fatal(err)
				}
				for rel, content := range got {
					p := filepath.Join(golden, filepath.FromSlash(rel))
					if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
						t.Fatal(err)
					}
				}
				return
			}
			want := tree(t, golden)
			if strings.Join(sortedKeys(got), ",") != strings.Join(sortedKeys(want), ",") {
				t.Fatalf("file set differs\n got: %v\nwant: %v", sortedKeys(got), sortedKeys(want))
			}
			for rel, content := range want {
				if got[rel] != content {
					t.Errorf("%s differs\n--- got ---\n%s\n--- want ---\n%s", rel, got[rel], content)
				}
			}
		})
	}
}

func TestTwoFailingBucketsKeepSeparateFiles(t *testing.T) {
	out := filepath.Join(t.TempDir(), "remediation")
	if _, err := execute(t, "remediate", "--prowler", "testdata/prowler_two_buckets.json", "--out", out); err != nil {
		t.Fatal(err)
	}
	files := tree(t, out)
	one := files["terraform/s3_public_access_block__bucket-one.tf"]
	two := files["terraform/s3_public_access_block__bucket-two.tf"]
	if !strings.Contains(one, `bucket = "bucket-one"`) {
		t.Errorf("bucket-one file wrong or missing:\n%s", one)
	}
	if !strings.Contains(two, `bucket = "bucket-two"`) {
		t.Errorf("bucket-two file wrong or missing:\n%s", two)
	}
	mapping := files["mapping.md"]
	for rel := range files {
		if strings.HasPrefix(rel, "terraform/") && !strings.Contains(mapping, rel) {
			t.Errorf("%s is not listed in mapping.md", rel)
		}
	}
	for _, line := range strings.Split(mapping, "\n") {
		if !strings.Contains(line, "| remediated |") {
			continue
		}
		cols := strings.Split(line, "|")
		for _, f := range strings.Split(strings.TrimSpace(cols[5]), ", ") {
			if _, ok := files[f]; !ok {
				t.Errorf("mapping.md points to missing file %q", f)
			}
		}
	}
	if strings.Count(mapping, "| remediated |") != 3 {
		t.Errorf("want 3 remediated rows:\n%s", mapping)
	}
}

func TestInvalidResourceIDIsSkippedNeverInjected(t *testing.T) {
	out := filepath.Join(t.TempDir(), "remediation")
	if _, err := execute(t, "remediate", "--prowler", "testdata/prowler_two_buckets.json", "--out", out, "--export-evidence"); err != nil {
		t.Fatal(err)
	}
	files := tree(t, out)
	for rel, content := range files {
		if strings.HasSuffix(rel, ".tf") && strings.Contains(content, "aws_iam_user") {
			t.Errorf("%s contains injected resource", rel)
		}
	}
	for _, name := range []string{"mapping.md", "evidence.md"} {
		if !strings.Contains(files[name], "skipped: invalid resource id") {
			t.Errorf("%s lacks the skipped row", name)
		}
	}
}

func TestUnmappedAndGuidanceRowsListed(t *testing.T) {
	out := filepath.Join(t.TempDir(), "remediation")
	if _, err := execute(t, "remediate", "--prowler", "testdata/prowler_two_buckets.json", "--out", out, "--export-evidence"); err != nil {
		t.Fatal(err)
	}
	files := tree(t, out)
	for _, name := range []string{"mapping.md", "evidence.md"} {
		if !strings.Contains(files[name], "iam_root_mfa_enabled") || !strings.Contains(files[name], "no mapping") {
			t.Errorf("%s lacks the unmapped FAIL row", name)
		}
		if !strings.Contains(files[name], "eks_cluster_not_publicly_accessible") || !strings.Contains(files[name], "guidance only") {
			t.Errorf("%s lacks the guidance row", name)
		}
	}
}

func TestKyvernoPoliciesAreClusterWideAndDeduped(t *testing.T) {
	out := filepath.Join(t.TempDir(), "remediation")
	if _, err := execute(t, "remediate", "--kube-bench", "testdata/kube_bench.json", "--out", out); err != nil {
		t.Fatal(err)
	}
	files := tree(t, out)
	var policies []string
	for rel := range files {
		if strings.HasPrefix(rel, "kyverno/") {
			policies = append(policies, rel)
		}
	}
	sort.Strings(policies)
	want := "kyverno/block_hostnet.yaml,kyverno/block_privileged.yaml,kyverno/require_nonroot.yaml"
	if strings.Join(policies, ",") != want {
		t.Errorf("policies = %v", policies)
	}
	mappingMD := files["mapping.md"]
	hasEtcd := false
	for _, line := range strings.Split(mappingMD, "\n") {
		if strings.Contains(line, "| 1.1.12 |") {
			hasEtcd = true
			if !strings.Contains(line, "| no mapping |") {
				t.Errorf("etcd check must stay unmapped: %s", line)
			}
		}
	}
	if !hasEtcd {
		t.Error("failed etcd check is not listed")
	}
	for _, id := range []string{"5.2.2", "5.2.5", "5.2.7"} {
		if !strings.Contains(mappingMD, "| "+id+" |") || !strings.Contains(mappingMD, "manual (WARN)") {
			t.Errorf("manual WARN control %s is not remediated or not marked", id)
		}
	}
	for _, id := range []string{"5.2.1", "5.2.3", "5.2.4", "5.2.6"} {
		if strings.Contains(mappingMD, "| "+id+" |") {
			t.Errorf("unmapped manual WARN control %s must not be listed", id)
		}
	}
}

func TestNothingGeneratedIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	in := filepath.Join(dir, "p.json")
	data := `[{"CheckID":"iam_root_mfa_enabled","Status":"FAIL","ResourceId":"root"},{"CheckID":"x","Status":"PASS","ResourceId":"y"}]`
	if err := os.WriteFile(in, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}
	out := filepath.Join(dir, "out")
	if _, err := execute(t, "remediate", "--prowler", in, "--out", out, "--export-evidence"); err != nil {
		t.Fatalf("unmapped findings must not fail the run: %v", err)
	}
	files := tree(t, out)
	if !strings.Contains(files["mapping.md"], "iam_root_mfa_enabled") || files["evidence.md"] == "" {
		t.Errorf("reports missing: %v", sortedKeys(files))
	}
}

func TestErrorsAreReturned(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(bad, []byte(`{"Findings":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	cases := map[string][]string{
		"no inputs":        {"remediate", "--out", dir},
		"missing file":     {"remediate", "--prowler", filepath.Join(dir, "none.json"), "--out", dir},
		"unsupported json": {"remediate", "--prowler", bad, "--out", dir},
		"bad kube-bench":   {"remediate", "--kube-bench", bad, "--out", dir},
		"unknown flag":     {"remediate", "--nope"},
	}
	for name, args := range cases {
		if _, err := execute(t, args...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestVersionFlag(t *testing.T) {
	out, err := execute(t, "--version")
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out) != "k8s-remediate-nis2 dev" {
		t.Errorf("version output = %q", out)
	}
}

func TestEvidenceHasHashAndDisclaimer(t *testing.T) {
	out := filepath.Join(t.TempDir(), "remediation")
	if _, err := execute(t, "remediate", "--prowler", "testdata/prowler_ocsf.json", "--out", out, "--export-evidence"); err != nil {
		t.Fatal(err)
	}
	ev := tree(t, out)["evidence.md"]
	for _, want := range []string{"SHA-256", "does not certify compliance", "testdata/prowler_ocsf.json"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence.md lacks %q", want)
		}
	}
}

func TestAWSGapsStatuses(t *testing.T) {
	out := filepath.Join(t.TempDir(), "remediation")
	if _, err := execute(t, "remediate", "--prowler", "testdata/prowler_aws_gaps.json", "--out", out); err != nil {
		t.Fatal(err)
	}
	files := tree(t, out)
	want := map[string]string{
		"ec2_ebs_default_encryption":                 "remediated",
		"s3_bucket_acl_prohibited":                   "remediated",
		"s3_bucket_secure_transport_policy":          "remediated",
		"s3_bucket_server_access_logging_enabled":    "remediated",
		"eks_cluster_private_nodes_enabled":          "guidance only",
		"ec2_networkacl_allow_ingress_any_port":      "guidance only",
		"ec2_networkacl_allow_ingress_tcp_port_22":   "guidance only",
		"ec2_networkacl_allow_ingress_tcp_port_3389": "guidance only",
	}
	got := map[string]string{}
	for _, line := range strings.Split(files["mapping.md"], "\n") {
		cols := strings.Split(line, "|")
		if len(cols) > 7 && strings.TrimSpace(cols[1]) == "prowler" {
			got[strings.TrimSpace(cols[2])] = strings.TrimSpace(cols[6])
		}
	}
	for check, status := range want {
		if got[check] != status {
			t.Errorf("%s: status = %q, want %q", check, got[check], status)
		}
	}
	if _, ok := files["terraform/ebs_default_encryption__000000000000_us-east-1.tf"]; !ok {
		t.Errorf("regional EBS file missing: %v", sortedKeys(files))
	}
	if strings.Count(files["mapping.md"], "s3_bucket_secure_transport_policy") != 2 {
		t.Errorf("the PASS record must not appear in mapping.md:\n%s", files["mapping.md"])
	}
}
