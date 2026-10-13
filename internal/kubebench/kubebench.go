package kubebench

import (
	"encoding/json"
	"errors"

	"github.com/nis2rem/k8s-remediate-nis2/internal/finding"
)

type benchDoc struct {
	Controls []struct {
		ID    string `json:"id"`
		Tests []struct {
			Section string `json:"section"`
			Results []struct {
				TestNumber string `json:"test_number"`
				Status     string `json:"status"`
				TestDesc   string `json:"test_desc"`
			} `json:"results"`
		} `json:"tests"`
	} `json:"Controls"`
}

// Parse decodes kube-bench JSON output.
func Parse(data []byte, sourceFile string) ([]finding.Finding, error) {
	var doc benchDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	if len(doc.Controls) == 0 {
		return nil, errors.New("no Controls in kube-bench JSON: " + sourceFile)
	}
	var out []finding.Finding
	for _, c := range doc.Controls {
		for _, t := range c.Tests {
			for _, r := range t.Results {
				out = append(out, finding.Finding{
					Scanner:     "kube-bench",
					CheckID:     r.TestNumber,
					Status:      r.Status,
					ResourceID:  "cluster",
					Region:      "",
					Severity:    "medium",
					Service:     "kubernetes",
					Description: r.TestDesc,
					SourceFile:  sourceFile,
				})
			}
		}
	}
	return out, nil
}
