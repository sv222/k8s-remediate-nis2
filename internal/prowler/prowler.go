package prowler

import (
	"encoding/json"
	"errors"
	"fmt"

	"github.com/nis2rem/k8s-remediate-nis2/internal/finding"
)

type v4Finding struct {
	FindingUID  string `json:"FindingID"`
	CheckID     string `json:"CheckID"`
	Status      string `json:"Status"`
	ResourceID  string `json:"ResourceID"`
	ResourceArn string `json:"ResourceArn"`
	Region      string `json:"Region"`
	Severity    string `json:"Severity"`
	Service     string `json:"Service"`
	Description string `json:"Description"`
}

type v3Wrapper struct {
	Findings []map[string]interface{} `json:"Findings"`
}

// Parse decodes Prowler v4 JSON (top-level array of findings).
func Parse(data []byte, sourceFile string) ([]finding.Finding, error) {
	var v4 []v4Finding
	if err := json.Unmarshal(data, &v4); err == nil && len(v4) > 0 && v4[0].FindingUID != "" {
		out := make([]finding.Finding, 0, len(v4))
		for _, f := range v4 {
			res := f.ResourceID
			if res == "" {
				res = f.ResourceArn
			}
			out = append(out, finding.Finding{
				Scanner: "prowler", CheckID: f.CheckID, Status: f.Status,
				ResourceID: res, Region: f.Region, Severity: f.Severity,
				Service: f.Service, Description: f.Description, SourceFile: sourceFile,
			})
		}
		return out, nil
	}
	var probe map[string]json.RawMessage
	if err := json.Unmarshal(data, &probe); err == nil {
		if _, hasFindings := probe["Findings"]; hasFindings {
			var v3 v3Wrapper
			_ = json.Unmarshal(data, &v3)
			return nil, fmt.Errorf("prowler v3 output detected (%d findings): re-run with prowler v4 (`prowler aws -M json-oosf` or v4 default JSON); %s", len(v3.Findings), sourceFile)
		}
	}
	if len(v4) == 0 {
		return nil, errors.New("empty prowler findings: " + sourceFile)
	}
	return nil, errors.New("unrecognized prowler JSON layout: " + sourceFile)
}
