package render

import (
	"errors"
	"io/fs"
	"strings"
	"testing"

	"sigs.k8s.io/yaml"

	"github.com/sv222/k8s-remediate-nis2/internal/finding"
	"github.com/sv222/k8s-remediate-nis2/mapping"
)

func s3Entry() mapping.Entry {
	return mapping.Entry{
		Scanner: "prowler", CheckID: "s3_bucket_level_public_access_block",
		Title:     "S3 bucket without Block Public Access",
		Articles:  []string{"NIS2 Art.21(2)(i)"},
		Templates: []string{"terraform/s3_public_access_block.tf"},
	}
}

func TestRenderTerraformInterpolates(t *testing.T) {
	f := finding.Finding{Scanner: "prowler", CheckID: "s3_bucket_level_public_access_block", ResourceID: "company-frontend-assets"}
	files, err := Render(s3Entry(), f)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].RelPath != "terraform/s3_public_access_block__company-frontend-assets.tf" {
		t.Fatalf("files = %+v", files)
	}
	if !strings.Contains(files[0].Content, `"remediation_company-frontend-assets"`) {
		t.Errorf("sanitized resource id missing:\n%s", files[0].Content)
	}
	if !strings.Contains(files[0].Content, `bucket = "company-frontend-assets"`) {
		t.Errorf("resource id missing:\n%s", files[0].Content)
	}
}

func TestRenderS3ARNBecomesBucketName(t *testing.T) {
	for _, id := range []string{"arn:aws:s3:::company-frontend-assets", "arn:aws:s3:::company-frontend-assets/some/key"} {
		files, err := Render(s3Entry(), finding.Finding{ResourceID: id})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(files[0].Content, `bucket = "company-frontend-assets"`) {
			t.Errorf("%s: bucket not extracted:\n%s", id, files[0].Content)
		}
		if strings.Contains(files[0].Content, "arn:") {
			t.Errorf("%s: arn leaked into output", id)
		}
	}
}

func TestRenderEmptyResourceUsesPlaceholder(t *testing.T) {
	files, err := Render(s3Entry(), finding.Finding{})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(files[0].Content, `bucket = "<RESOURCE_IDENTIFIER>"`) {
		t.Errorf("placeholder missing:\n%s", files[0].Content)
	}
	if files[0].RelPath != "terraform/s3_public_access_block__RESOURCE_IDENTIFIER.tf" {
		t.Errorf("path = %s", files[0].RelPath)
	}
}

func TestRenderRejectsInjectedResourceID(t *testing.T) {
	bad := []string{
		"b\"\n}\nresource \"aws_iam_user\" \"x\" {",
		"bucket name",
		"a${var.x}",
		"x\ny",
		"a;b",
		"a%b",
		"a<b>",
		"arn:aws:s3:::ok\n# injected",
		strings.Repeat("a", maxResourceIDLen+1),
	}
	for _, id := range bad {
		files, err := Render(s3Entry(), finding.Finding{ResourceID: id})
		if !errors.Is(err, ErrInvalidResourceID) {
			t.Errorf("id %q: err = %v, want ErrInvalidResourceID", id, err)
		}
		if files != nil {
			t.Errorf("id %q: files rendered despite invalid id", id)
		}
	}
}

func TestRenderAcceptsRealIdentifiers(t *testing.T) {
	good := []string{
		"company-frontend-assets", "my.bucket.name", "sg-0a1b2c3d4e5f60718",
		"arn:aws:ec2:eu-central-1:123456789012:security-group/sg-0a1b2c3d4e5f60718",
		"manufacturer-api:7", "user@example.com+tag=1,2",
	}
	for _, id := range good {
		if err := ValidateResourceID(id); err != nil {
			t.Errorf("id %q: %v", id, err)
		}
	}
}

func TestSanitizeIsUniqueForLossyNames(t *testing.T) {
	if got := SanitizeResourceID("sg-0abc"); got != "sg-0abc" {
		t.Errorf("clean id changed: %q", got)
	}
	a, b := SanitizeResourceID("a.b"), SanitizeResourceID("a_b")
	if a == b {
		t.Errorf("collision: %q == %q", a, b)
	}
	if !strings.HasPrefix(a, "a_b_") {
		t.Errorf("lossy name %q lacks hash suffix", a)
	}
	if SanitizeResourceID("a.b") != a {
		t.Error("sanitize is not deterministic")
	}
	if got := SanitizeResourceID(""); got != "RESOURCE_IDENTIFIER" {
		t.Errorf("fallback got %q", got)
	}
	long := SanitizeResourceID(strings.Repeat("a", 200))
	if len(long) > maxNameLen+7 {
		t.Errorf("long name not truncated: %d", len(long))
	}
}

func TestTwoResourcesGetDistinctFiles(t *testing.T) {
	set := NewSet()
	for _, id := range []string{"bucket-one", "bucket-two"} {
		files, err := Render(s3Entry(), finding.Finding{ResourceID: id})
		if err != nil {
			t.Fatal(err)
		}
		set.Add(files)
	}
	got := set.Files()
	if len(got) != 2 {
		t.Fatalf("files = %d, want 2", len(got))
	}
	if got[0].RelPath == got[1].RelPath {
		t.Error("distinct buckets share a path")
	}
}

func TestSharedTemplatesRenderOnce(t *testing.T) {
	e := mapping.Entry{Title: "x", Articles: []string{"a"}, SharedTemplates: []string{"kyverno/require_nonroot.yaml"}}
	set := NewSet()
	for _, id := range []string{"cluster", "cluster"} {
		files, err := Render(e, finding.Finding{ResourceID: id})
		if err != nil {
			t.Fatal(err)
		}
		set.Add(files)
	}
	if got := set.Files(); len(got) != 1 || got[0].RelPath != "kyverno/require_nonroot.yaml" {
		t.Fatalf("files = %+v", got)
	}
}

func TestSecurityGroupNeverOpensToInternet(t *testing.T) {
	entries, err := mapping.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.CheckID != "ec2_securitygroup_allow_ingress_from_internet_to_any_port" {
			continue
		}
		files, err := Render(e, finding.Finding{ResourceID: "sg-0a1b2c3d4e5f60718"})
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 2 {
			t.Fatalf("files = %d, want rule and variables", len(files))
		}
		for _, f := range files {
			if strings.Contains(f.Content, "0.0.0.0/0") || strings.Contains(f.Content, "::/0") {
				t.Errorf("%s contains an internet-wide CIDR:\n%s", f.RelPath, f.Content)
			}
		}
		rule := files[0].Content
		if !strings.Contains(rule, "var.allowed_cidr") || !strings.Contains(rule, `security_group_id = "sg-0a1b2c3d4e5f60718"`) {
			t.Errorf("rule not bound to variables:\n%s", rule)
		}
		if !strings.Contains(rule, "aws_vpc_security_group_ingress_rule") {
			t.Errorf("unexpected resource type:\n%s", rule)
		}
	}
}

func TestEveryMappedTemplateRenders(t *testing.T) {
	entries, err := mapping.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		files, err := Render(e, finding.Finding{ResourceID: "example-id"})
		if err != nil {
			t.Errorf("%s: %v", e.Title, err)
			continue
		}
		for _, f := range files {
			if strings.HasPrefix(f.RelPath, "kyverno/") {
				var doc map[string]any
				if err := yaml.Unmarshal([]byte(f.Content), &doc); err != nil {
					t.Errorf("%s: invalid YAML: %v", f.RelPath, err)
					continue
				}
				if doc["kind"] != "ClusterPolicy" {
					t.Errorf("%s: kind = %v", f.RelPath, doc["kind"])
				}
				spec := doc["spec"].(map[string]any)
				if spec["validationFailureAction"] != "Audit" {
					t.Errorf("%s: validationFailureAction = %v, want Audit", f.RelPath, spec["validationFailureAction"])
				}
				for _, ns := range []string{"kube-system", "kube-public", "kube-node-lease", "kyverno"} {
					if !strings.Contains(f.Content, ns) {
						t.Errorf("%s: namespace %s not excluded", f.RelPath, ns)
					}
				}
				meta := doc["metadata"].(map[string]any)
				if strings.Contains(meta["name"].(string), "example") || strings.Contains(meta["name"].(string), "cluster") {
					t.Errorf("%s: policy name depends on a resource: %v", f.RelPath, meta["name"])
				}
			}
			if strings.Contains(f.Content, "ARN_PLACEHOLDER") {
				t.Errorf("%s: placeholder ARN left in output", f.RelPath)
			}
		}
	}
}

func TestAllTemplatesParseAndExecute(t *testing.T) {
	err := fs.WalkDir(mapping.TemplatesFS, "templates", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if _, err := execute(strings.TrimPrefix(p, "templates/"), resourceData{ResourceID: "x", SanitizedResourceID: "x", Title: "t", Articles: []string{"a"}}); err != nil {
			t.Errorf("%s: %v", p, err)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
