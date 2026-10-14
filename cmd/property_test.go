package cmd

import (
	"math/rand"
	"path/filepath"
	"strings"
	"testing"
)

func TestPropertyRandomResourceIDsThroughTheCLI(t *testing.T) {
	r := rand.New(rand.NewSource(7))
	alphabet := "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.-_:/@+=, \"`|[]()!*<>"
	checks := []string{
		"s3_bucket_level_public_access_block", "s3_bucket_default_encryption", "s3_bucket_kms_encryption",
		"s3_bucket_secure_transport_policy", checkSSH, checkRDP, "ec2_securitygroup_allow_ingress_from_internet_to_any_port", "iam_root_mfa_enabled",
	}
	var recs []rec
	for i := 0; i < 250; i++ {
		b := make([]byte, 1+r.Intn(30))
		for j := range b {
			b[j] = alphabet[r.Intn(len(alphabet))]
		}
		recs = append(recs, rec{check: checks[r.Intn(len(checks))], status: "FAIL", resource: string(b)})
	}
	_, files, err := runWith(t, legacyJSON(recs...), "--export-evidence")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	for rel, content := range files {
		if !filepath.IsLocal(filepath.FromSlash(rel)) {
			t.Errorf("%s is outside the output directory", rel)
		}
		low := strings.ToLower(rel)
		if prev, ok := seen[low]; ok {
			t.Errorf("%s and %s collide on a case-insensitive file system", prev, rel)
		}
		seen[low] = rel
		if strings.HasSuffix(rel, ".tf") && (strings.Contains(content, "0.0.0.0/0") || strings.Contains(content, "::/0")) {
			t.Errorf("%s contains an internet-wide CIDR", rel)
		}
	}
	for _, name := range []string{"mapping.md", "evidence.md"} {
		if strings.Contains(files[name], "![") || strings.Contains(files[name], "](") {
			t.Errorf("%s contains markdown link or image syntax", name)
		}
	}
}
