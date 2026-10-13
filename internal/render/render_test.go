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
	checked := 0
	for _, e := range entries {
		if len(e.Templates) != 1 || e.Templates[0] != "terraform/sg_restrict_ingress.tf" {
			continue
		}
		checked++
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
	if checked < 5 {
		t.Errorf("checked %d security group entries, want at least 5", checked)
	}
}

func TestEveryMappedTemplateRenders(t *testing.T) {
	entries, err := mapping.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		files, err := Render(e, finding.Finding{ResourceID: "example-id", Region: "us-east-1"})
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
				if doc["apiVersion"] != "policies.kyverno.io/v1" || doc["kind"] != "ValidatingPolicy" {
					t.Errorf("%s: apiVersion = %v, kind = %v", f.RelPath, doc["apiVersion"], doc["kind"])
				}
				spec := doc["spec"].(map[string]any)
				if actions, _ := spec["validationActions"].([]any); len(actions) != 1 || actions[0] != "Audit" {
					t.Errorf("%s: validationActions = %v, want [Audit]", f.RelPath, spec["validationActions"])
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

func entryFor(t *testing.T, check string) mapping.Entry {
	t.Helper()
	e, ok, err := mapping.For(finding.Finding{Scanner: "prowler", CheckID: check})
	if err != nil || !ok {
		t.Fatalf("%s: no mapping (ok=%v err=%v)", check, ok, err)
	}
	return e
}

func TestRegionalTemplateNeedsRegion(t *testing.T) {
	e := entryFor(t, "ec2_ebs_default_encryption")
	for _, region := range []string{"", "us east 1", "us-east-1\"}", "x"} {
		_, err := Render(e, finding.Finding{ResourceID: "000000000000", Region: region})
		if !errors.Is(err, ErrInvalidResourceID) {
			t.Errorf("region %q: err = %v, want ErrInvalidResourceID", region, err)
		}
	}
}

func TestRegionalTemplateGetsOneFilePerRegion(t *testing.T) {
	e := entryFor(t, "ec2_ebs_default_encryption")
	seen := map[string]bool{}
	for _, region := range []string{"us-east-1", "eu-west-1", "us-gov-west-1"} {
		files, err := Render(e, finding.Finding{ResourceID: "000000000000", Region: region})
		if err != nil {
			t.Fatal(err)
		}
		if len(files) != 1 || seen[files[0].RelPath] {
			t.Fatalf("region %s: files = %+v", region, files)
		}
		seen[files[0].RelPath] = true
		if !strings.Contains(files[0].Content, `region = "`+region+`"`) {
			t.Errorf("region %s missing:\n%s", region, files[0].Content)
		}
		if !strings.Contains(files[0].RelPath, "000000000000_"+region) {
			t.Errorf("path lacks region: %s", files[0].RelPath)
		}
	}
}

func TestRiskyTemplatesCarryLoudWarnings(t *testing.T) {
	cases := map[string][]string{
		"s3_bucket_secure_transport_policy": {"WARNING", "plain HTTP", "REPLACES the whole bucket policy", "s3_existing_bucket_policies"},
		"s3_bucket_acl_prohibited":          {"WARNING", "disables all ACLs"},
	}
	for check, wants := range cases {
		files, err := Render(entryFor(t, check), finding.Finding{ResourceID: "example-bucket", Region: "us-east-1"})
		if err != nil {
			t.Fatal(err)
		}
		head := strings.SplitN(files[0].Content, "\nresource ", 2)[0]
		head = strings.SplitN(head, "\ndata ", 2)[0]
		for _, w := range wants {
			if !strings.Contains(head, w) {
				t.Errorf("%s: header lacks %q:\n%s", check, w, head)
			}
		}
	}
}

func TestNoTemplateWidensAccess(t *testing.T) {
	entries, err := mapping.Load()
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		files, err := Render(e, finding.Finding{ResourceID: "example-id", Region: "us-east-1"})
		if err != nil {
			t.Fatal(err)
		}
		for _, f := range files {
			if !strings.HasPrefix(f.RelPath, "terraform/") {
				continue
			}
			for _, bad := range []string{"0.0.0.0/0", "::/0", `"Allow"`, "public-read", `effect  = "Allow"`, `effect = "Allow"`} {
				if strings.Contains(f.Content, bad) {
					t.Errorf("%s contains %q", f.RelPath, bad)
				}
			}
		}
	}
}

func TestSecureTransportOnlyDenies(t *testing.T) {
	files, err := Render(entryFor(t, "s3_bucket_secure_transport_policy"), finding.Finding{ResourceID: "example-bucket"})
	if err != nil {
		t.Fatal(err)
	}
	c := files[0].Content
	for _, w := range []string{`effect  = "Deny"`, `variable = "aws:SecureTransport"`, `values   = ["false"]`, `arn:${data.aws_partition.current.partition}:s3:::example-bucket/*`} {
		if !strings.Contains(c, w) {
			t.Errorf("missing %q:\n%s", w, c)
		}
	}
	if strings.Count(c, "statement {") != 1 {
		t.Errorf("want exactly one statement:\n%s", c)
	}
}

func TestNetworkACLAndEKSAreGuidanceOnly(t *testing.T) {
	for _, check := range []string{
		"ec2_networkacl_allow_ingress_any_port",
		"ec2_networkacl_allow_ingress_tcp_port_22",
		"ec2_networkacl_allow_ingress_tcp_port_3389",
		"eks_cluster_private_nodes_enabled",
	} {
		e := entryFor(t, check)
		if len(e.Templates) != 0 || len(e.SharedTemplates) != 0 || e.Guidance == "" {
			t.Errorf("%s: must be guidance only: %+v", check, e)
		}
	}
}
