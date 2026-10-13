package kubebench

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/sv222/k8s-remediate-nis2/internal/finding"
)

type control struct {
	ID              string `json:"id"`
	Version         string `json:"version"`
	DetectedVersion string `json:"detected_version"`
	Tests           []struct {
		Section string `json:"section"`
		Results []struct {
			TestNumber string `json:"test_number"`
			Status     string `json:"status"`
			TestDesc   string `json:"test_desc"`
			Type       string `json:"type"`
		} `json:"results"`
	} `json:"tests"`
}

type benchDoc struct {
	Controls []control `json:"Controls"`
}

func Parse(data []byte, sourceFile string) ([]finding.Finding, error) {
	trimmed := bytes.TrimSpace(data)
	if len(trimmed) == 0 {
		return nil, fmt.Errorf("%s: empty file", sourceFile)
	}
	var controls []control
	if trimmed[0] == '[' {
		if err := json.Unmarshal(trimmed, &controls); err != nil {
			return nil, fmt.Errorf("%s: invalid kube-bench JSON: %w", sourceFile, err)
		}
	} else {
		var doc benchDoc
		if err := json.Unmarshal(trimmed, &doc); err != nil {
			return nil, fmt.Errorf("%s: invalid kube-bench JSON: %w", sourceFile, err)
		}
		controls = doc.Controls
	}
	if len(controls) == 0 {
		return nil, errors.New("no Controls in kube-bench JSON: " + sourceFile)
	}
	var out []finding.Finding
	for _, c := range controls {
		for _, t := range c.Tests {
			for _, r := range t.Results {
				out = append(out, finding.Finding{
					Scanner:     "kube-bench",
					CheckID:     r.TestNumber,
					Benchmark:   c.Version,
					Status:      strings.ToUpper(strings.TrimSpace(r.Status)),
					Manual:      strings.EqualFold(strings.TrimSpace(r.Type), "manual"),
					ResourceID:  "cluster",
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
