package out

import (
	"strings"
	"testing"
)

func markdownRows() []SummaryRow {
	return []SummaryRow{
		{Scanner: "prowler", CheckID: "s3_bucket_public_access", Title: "S3 bucket publicly accessible", ResourceID: "bucket-one",
			Region: "eu-central-1", Account: "123456789012", Files: []string{"terraform/s3_public_access_block__bucket-one.tf"}, Status: StatusCodeGenerated},
		{Scanner: "prowler", CheckID: "s3_bucket_public_access", Title: "S3 bucket publicly accessible", ResourceID: "bucket-two",
			Region: "eu-central-1", Account: "123456789012", Files: []string{"terraform/s3_public_access_block__bucket-two.tf"}, Status: StatusCodeGenerated},
		{Scanner: "prowler", CheckID: "eks_cluster_not_publicly_accessible", Title: "EKS cluster not publicly accessible", ResourceID: "prod",
			Region: "eu-central-1", Account: "123456789012", Status: StatusGuidanceOnly, Note: "Manual steps."},
		{Scanner: "prowler", CheckID: "iam_root_hardware_mfa_enabled", Title: "Hardware MFA for the root account", ResourceID: "root",
			Status: StatusNoMapping},
	}
}

func linesInOrder(t *testing.T, s string, want []string) {
	t.Helper()
	pos := 0
	for _, w := range want {
		i := strings.Index(s[pos:], w)
		if i < 0 {
			t.Errorf("output lacks %q in order:\n%s", w, s)
			continue
		}
		pos += i + len(w)
	}
}

func TestMarkdownGroupsByFindingAndListsFiles(t *testing.T) {
	s := string(Markdown(Report{Rows: markdownRows()}))
	linesInOrder(t, s, []string{
		"# Remediation summary",
		"> Nothing was applied. These are proposals; apply them, then re-scan to confirm the findings are fixed.",
		"## `prowler/s3_bucket_public_access` — S3 bucket publicly accessible",
		"- `terraform/s3_public_access_block__bucket-one.tf` — `bucket-one`, `eu-central-1`, account `123456789012` — `code generated`",
		"- `terraform/s3_public_access_block__bucket-two.tf` — `bucket-two`, `eu-central-1`, account `123456789012` — `code generated`",
		"## `prowler/eks_cluster_not_publicly_accessible` — EKS cluster not publicly accessible",
		"- `prod`, `eu-central-1`, account `123456789012` — `guidance only`",
		"## `prowler/iam_root_hardware_mfa_enabled` — Hardware MFA for the root account",
		"- `root` — `no mapping`",
	})
	if bullets := strings.Count(s, "\n- "); bullets != 4 {
		t.Errorf("%d bullet lines, want 4 (one per file, one per fileless row):\n%s", bullets, s)
	}
	if strings.Contains(s, "Manual steps.") {
		t.Error("the long note must not repeat in the one-line summary")
	}
}

func TestMarkdownIsDeterministic(t *testing.T) {
	rep := Report{Rows: markdownRows()}
	a := Markdown(rep)
	b := Markdown(rep)
	if string(a) != string(b) {
		t.Error("two runs of the same report gave different bytes")
	}
}

func TestMarkdownWithoutRows(t *testing.T) {
	s := string(Markdown(Report{}))
	if !strings.HasPrefix(s, "# Remediation summary\n") || !strings.Contains(s, "No failed findings.") {
		t.Errorf("empty report output is wrong:\n%s", s)
	}
	if strings.Contains(s, "## ") || strings.Contains(s, "\n- ") {
		t.Errorf("empty report must have no groups:\n%s", s)
	}
}

func TestMarkdownEscapesUntrustedText(t *testing.T) {
	row := SummaryRow{
		Scanner: "prowler", CheckID: "a|b", Title: "![x](https://attacker.example/p.png) `c` *b* a|b",
		ResourceID: "line1\nline2 ![x](https://attacker.example/p.png)", Files: []string{"f|g"}, Status: StatusSkipped,
	}
	s := string(Markdown(Report{Rows: []SummaryRow{row}}))
	for _, bad := range []string{"![x](https://attacker.example/p.png)", "`c`", "f|g", "a|b", "\nline2"} {
		if strings.Contains(s, bad) {
			t.Errorf("markdown output keeps %q:\n%s", bad, s)
		}
	}
	if !strings.Contains(s, "## `prowler/a?b`") {
		t.Errorf("check id with a hostile character is not sanitized:\n%s", s)
	}
	if !strings.Contains(s, "`f?g`") {
		t.Errorf("file name with a hostile character is not sanitized:\n%s", s)
	}
	if !strings.Contains(s, "`line1?line2???x??https://attacker.example/p.png?`") {
		t.Errorf("resource id with a hostile character is not sanitized:\n%s", s)
	}
}
