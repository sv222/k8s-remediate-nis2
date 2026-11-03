package out

import (
	"encoding/json"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

func TestSARIF(t *testing.T) {
	absSrc, err := filepath.Abs(filepath.Join(t.TempDir(), "abs dir", "bench.json"))
	if err != nil {
		t.Fatal(err)
	}
	slashed := filepath.ToSlash(absSrc)
	if !strings.HasPrefix(slashed, "/") {
		slashed = "/" + slashed
	}
	wantURI := (&url.URL{Scheme: "file", Path: slashed}).String()
	if !strings.HasPrefix(wantURI, "file:///") || !strings.HasSuffix(wantURI, "/abs%20dir/bench.json") {
		t.Fatalf("bad expected uri %q", wantURI)
	}
	rep := Report{Rows: []SummaryRow{
		{Scanner: "prowler", CheckID: "s3_bucket_public_access", Title: "S3 bucket publicly accessible", Source: "in/p.json", ResourceID: "b1",
			Severity: "high", Region: "us-east-1", Account: "1", Articles: []string{"NIS2 Art.21(2)(i)"},
			Files: []string{"terraform/s3_public_access_block__b1.tf"}, Status: StatusCodeGenerated, Note: "Not applied."},
		{Scanner: "prowler", CheckID: "s3_bucket_public_access", Title: "S3 bucket publicly accessible", Source: "in/p.json", ResourceID: "b2",
			Severity: "high", Status: StatusCodeGenerated},
		{Scanner: "kube-bench", CheckID: "1.2.5", Title: "Ensure x (Automated)", Source: absSrc, ResourceID: "cluster",
			Severity: "medium", Status: StatusNoMapping},
		{Scanner: "prowler", CheckID: "x", Source: "p.json", ResourceID: "r", Severity: "low", Status: StatusNoMapping},
	}}
	data, err := SARIF(rep, "out")
	if err != nil {
		t.Fatal(err)
	}
	var log struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Name  string `json:"name"`
					Rules []struct {
						ID               string                `json:"id"`
						ShortDescription struct{ Text string } `json:"shortDescription"`
					} `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Message   struct{ Text string }
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
				PartialFingerprints map[string]string `json:"partialFingerprints"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 || log.Runs[0].Tool.Driver.Name != "k8s-remediate-nis2" {
		t.Fatalf("bad log: %s", data)
	}
	run := log.Runs[0]
	if len(run.Tool.Driver.Rules) != 3 || run.Tool.Driver.Rules[0].ID != "prowler/s3_bucket_public_access" ||
		run.Tool.Driver.Rules[0].ShortDescription.Text != "S3 bucket publicly accessible" ||
		run.Tool.Driver.Rules[2].ShortDescription.Text != "prowler check x" {
		t.Errorf("rules = %+v", run.Tool.Driver.Rules)
	}
	if len(run.Results) != 4 {
		t.Fatalf("results = %d, want 4", len(run.Results))
	}
	want := []struct{ rule, level, uri string }{
		{"prowler/s3_bucket_public_access", "error", "out/terraform/s3_public_access_block__b1.tf"},
		{"prowler/s3_bucket_public_access", "error", "in/p.json"},
		{"kube-bench/1.2.5", "warning", wantURI},
		{"prowler/x", "note", "p.json"},
	}
	for i, w := range want {
		r := run.Results[i]
		if r.RuleID != w.rule || r.Level != w.level || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != w.uri ||
			run.Tool.Driver.Rules[r.RuleIndex].ID != w.rule {
			t.Errorf("result %d = %+v, want %+v", i, r, w)
		}
		if r.PartialFingerprints["findingHash/v1"] == "" {
			t.Errorf("result %d has no fingerprint", i)
		}
	}
	if run.Results[0].PartialFingerprints["findingHash/v1"] == run.Results[1].PartialFingerprints["findingHash/v1"] {
		t.Error("two resources share a fingerprint")
	}
	if run.Results[0].Message.Text != "code generated: s3_bucket_public_access on b1. Not applied." {
		t.Errorf("message = %q", run.Results[0].Message.Text)
	}
}

func TestSARIFWithoutRowsIsValid(t *testing.T) {
	data, err := SARIF(Report{}, "out")
	if err != nil {
		t.Fatal(err)
	}
	var log map[string]any
	if err := json.Unmarshal(data, &log); err != nil {
		t.Fatal(err)
	}
	runs := log["runs"].([]any)
	run := runs[0].(map[string]any)
	if res, ok := run["results"].([]any); !ok || len(res) != 0 {
		t.Errorf("results must be an empty array: %s", data)
	}
}
