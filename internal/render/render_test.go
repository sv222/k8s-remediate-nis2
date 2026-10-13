package render

import (
	"strings"
	"testing"

	"github.com/nis2rem/k8s-remediate-nis2/internal/finding"
	"github.com/nis2rem/k8s-remediate-nis2/mapping"
)

func TestRenderTerraformInterpolates(t *testing.T) {
	e := mapping.Entry{
		Scanner: "prowler", CheckID: "s3_bucket_public_access_block",
		Title: "S3 bucket without full public access block",
		Articles:  []string{"NIS2 Art.21(2)(j)"},
		Templates: []string{"terraform/s3_public_access_block.tf"},
	}
	f := finding.Finding{Scanner: "prowler", CheckID: "s3_bucket_public_access_block",
		ResourceID: "company-frontend-assets"}
	files, err := Render(e, f)
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 1 || files[0].RelPath != "terraform/s3_public_access_block.tf" {
		t.Fatalf("files = %+v", files)
	}
	if !strings.Contains(files[0].Content, `remediation_company_frontend_assets"`) {
		t.Errorf("sanitized resource id missing:\n%s", files[0].Content)
	}
	if !strings.Contains(files[0].Content, `bucket = "company-frontend-assets"`) {
		t.Errorf("resource id missing:\n%s", files[0].Content)
	}
}

func TestSanitize(t *testing.T) {
	if got := SanitizeResourceID("sg-0abc/123"); got != "sg_0abc_123" {
		t.Errorf("got %q", got)
	}
	if got := SanitizeResourceID(""); got != "RESOURCE_IDENTIFIER" {
		t.Errorf("fallback got %q", got)
	}
}
